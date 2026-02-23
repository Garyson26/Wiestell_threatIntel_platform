"""Feed management API endpoints."""

from uuid import UUID
from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.database import get_db
from app.models.feed import FeedSource
from app.schemas.feed import FeedCreate, FeedUpdate, FeedResponse

router = APIRouter()


@router.get("", response_model=list[FeedResponse])
async def list_feeds(db: AsyncSession = Depends(get_db)):
    """List all feed sources with their status."""
    result = await db.execute(select(FeedSource).order_by(FeedSource.name))
    feeds = result.scalars().all()
    return [FeedResponse.model_validate(f) for f in feeds]


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
async def update_feed(feed_id: UUID, update: FeedUpdate, db: AsyncSession = Depends(get_db)):
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
async def delete_feed(feed_id: UUID, db: AsyncSession = Depends(get_db)):
    """Remove a feed source."""
    result = await db.execute(select(FeedSource).where(FeedSource.id == feed_id))
    feed = result.scalar_one_or_none()
    if not feed:
        raise HTTPException(status_code=404, detail="Feed not found")

    await db.delete(feed)
    await db.flush()
    return {"status": "deleted", "feed_id": str(feed_id)}


@router.post("/{feed_id}/sync")
async def trigger_sync(feed_id: UUID, db: AsyncSession = Depends(get_db)):
    """Trigger manual feed sync."""
    result = await db.execute(select(FeedSource).where(FeedSource.id == feed_id))
    feed = result.scalar_one_or_none()
    if not feed:
        raise HTTPException(status_code=404, detail="Feed not found")

    # In production, this would dispatch a Celery task
    return {
        "status": "sync_queued",
        "feed_id": str(feed_id),
        "feed_name": feed.name,
        "message": f"Sync for {feed.name} has been queued",
    }


@router.get("/{feed_id}/logs")
async def get_sync_logs(feed_id: UUID, db: AsyncSession = Depends(get_db)):
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
                "timestamp": feed.last_sync_at.isoformat() if feed.last_sync_at else None,
                "status": feed.last_sync_status or "never_synced",
                "iocs_ingested": feed.ioc_count,
            }
        ],
    }
