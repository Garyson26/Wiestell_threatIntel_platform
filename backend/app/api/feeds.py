"""Feed management API endpoints."""

from fastapi import APIRouter, BackgroundTasks, Depends, HTTPException
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

import structlog
from app.database import get_db
from app.models.feed import FeedSource
from app.schemas.feed import FeedCreate, FeedUpdate, FeedResponse
from app.services.feed_scheduler import FEED_CONNECTORS, run_feed_sync
from app.utils import to_ist_str

logger = structlog.get_logger()

router = APIRouter()


@router.get("", response_model=list[FeedResponse])
async def list_feeds(db: AsyncSession = Depends(get_db)):
    """List all feed sources with their status."""
    try:
        result = await db.execute(select(FeedSource).order_by(FeedSource.name))
        feeds = result.scalars().all()
        return [FeedResponse.model_validate(f) for f in feeds]
    except Exception as e:
        logger.error("failed_to_list_feeds", error=str(e), error_type=type(e).__name__)
        raise HTTPException(
            status_code=500,
            detail="Failed to retrieve feed sources. Please try again."
        )


@router.post("", response_model=FeedResponse)
async def create_feed(feed_data: FeedCreate, db: AsyncSession = Depends(get_db)):
    """Add a custom feed source."""
    existing = await db.execute(
        select(FeedSource).where(FeedSource.slug == feed_data.slug)
    )
    if existing.scalar_one_or_none():
        raise HTTPException(status_code=409, detail="Feed with this slug already exists")

    feed = FeedSource(
        name=feed_data.name,
        slug=feed_data.slug,
        description=feed_data.description,
        feed_type=feed_data.feed_type,
        url=feed_data.url,
        api_key_env=feed_data.api_key_env,
        sync_frequency=feed_data.sync_frequency,
        config=feed_data.config or {},
    )
    db.add(feed)
    await db.flush()
    return FeedResponse.model_validate(feed)


@router.put("/{feed_id}", response_model=FeedResponse)
async def update_feed(feed_id: str, update: FeedUpdate, db: AsyncSession = Depends(get_db)):
    """Update feed configuration."""
    result = await db.execute(select(FeedSource).where(FeedSource.id == feed_id))
    feed = result.scalar_one_or_none()
    if not feed:
        raise HTTPException(status_code=404, detail="Feed not found")

    for field, value in update.model_dump(exclude_unset=True).items():
        setattr(feed, field, value)

    await db.flush()
    return FeedResponse.model_validate(feed)


@router.delete("/{feed_id}")
async def delete_feed(feed_id: str, db: AsyncSession = Depends(get_db)):
    """Remove a feed source."""
    result = await db.execute(select(FeedSource).where(FeedSource.id == feed_id))
    feed = result.scalar_one_or_none()
    if not feed:
        raise HTTPException(status_code=404, detail="Feed not found")

    await db.delete(feed)
    await db.flush()
    return {"status": "deleted", "feed_id": str(feed_id)}


@router.post("/{feed_id}/sync", status_code=202)
async def trigger_sync(feed_id: str, background_tasks: BackgroundTasks, db: AsyncSession = Depends(get_db)):
    """Queue a feed sync. Returns 202 immediately; ingestion runs in the background."""
    result = await db.execute(select(FeedSource).where(FeedSource.id == feed_id))
    feed = result.scalar_one_or_none()
    if not feed:
        raise HTTPException(status_code=404, detail="Feed not found")

    connector_path = FEED_CONNECTORS.get(feed.slug)
    if not connector_path:
        raise HTTPException(
            status_code=400,
            detail=f"No connector registered for feed slug '{feed.slug}'",
        )

    background_tasks.add_task(run_feed_sync, feed_id=feed_id, feed_slug=feed.slug, connector_path=connector_path)

    return {
        "status": "sync_started",
        "feed_id": str(feed_id),
        "feed_name": feed.name,
        "message": f"Sync for {feed.name} is running in the background.",
    }


@router.post("/sync-all", status_code=202)
async def sync_all_feeds(db: AsyncSession = Depends(get_db)):
    """
    Sync all overdue feeds. Designed for Vercel Cron jobs.
    
    This endpoint triggers synchronous feed syncs for all enabled feeds
    that are overdue based on their sync_frequency.
    
    ⚠️ Note: On Vercel, this runs synchronously within the 60s timeout limit.
    For production with many feeds, consider batching or using a queue.
    
    Usage with Vercel Cron:
    - vercel.json: {"path": "/api/v1/feeds/sync-all", "schedule": "0 * * * *"}
    - Runs every hour automatically
    """
    from datetime import datetime

    result = await db.execute(
        select(FeedSource).where(FeedSource.is_enabled == True)  # noqa: E712
    )
    feeds = result.scalars().all()
    
    now = datetime.utcnow()
    synced_results = []
    skipped_count = 0
    
    for feed in feeds:
        # Check if feed is overdue for sync
        freq = feed.sync_frequency or 3600  # default 1 hour
        last = feed.last_sync_at
        overdue = last is None or (now - last).total_seconds() >= freq
        
        if not overdue:
            skipped_count += 1
            continue
            
        connector_path = FEED_CONNECTORS.get(feed.slug)
        if not connector_path:
            logger.warning("cron_sync_no_connector", slug=feed.slug)
            synced_results.append({
                "feed_id": str(feed.id),
                "name": feed.name,
                "slug": feed.slug,
                "status": "error",
                "message": "No connector registered"
            })
            continue
        
        # Sync synchronously (blocking) - required for Vercel serverless
        try:
            await run_feed_sync(
                feed_id=str(feed.id),
                feed_slug=feed.slug,
                connector_path=connector_path
            )
            
            synced_results.append({
                "feed_id": str(feed.id),
                "name": feed.name,
                "slug": feed.slug,
                "status": "success",
                "last_sync": to_ist_str(feed.last_sync_at) if feed.last_sync_at else "never",
            })
            
            logger.info("cron_sync_success", feed=feed.slug, frequency=freq)
            
        except Exception as e:
            logger.error("cron_sync_failed", feed=feed.slug, error=str(e))
            synced_results.append({
                "feed_id": str(feed.id),
                "name": feed.name,
                "slug": feed.slug,
                "status": "failed",
                "error": str(e)
            })
    
    synced_count = len([r for r in synced_results if r.get("status") == "success"])
    failed_count = len([r for r in synced_results if r.get("status") == "failed"])
    
    return {
        "status": "completed",
        "synced_count": synced_count,
        "failed_count": failed_count,
        "skipped_count": skipped_count,
        "total_feeds": len(feeds),
        "results": synced_results,
        "message": f"Synced {synced_count} feed(s), {failed_count} failed, {skipped_count} skipped.",
    }


@router.get("/{feed_id}/logs")
async def get_sync_logs(feed_id: str, db: AsyncSession = Depends(get_db)):
    """Get recent sync logs for a feed."""
    result = await db.execute(select(FeedSource).where(FeedSource.id == feed_id))
    feed = result.scalar_one_or_none()
    if not feed:
        raise HTTPException(status_code=404, detail="Feed not found")

    return {
        "feed_id": str(feed.id),
        "feed_name": feed.name,
        "logs": [
            {
                "timestamp": to_ist_str(feed.last_sync_at),
                "status": feed.last_sync_status or "never_synced",
                "iocs_ingested": feed.ioc_count,
            }
        ],
    }
