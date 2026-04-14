"""Feed management API endpoints."""

from fastapi import APIRouter, BackgroundTasks, Depends, HTTPException, Query
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

# Temporarily disabled feeds — add/remove slugs as needed
_TEMP_DISABLED_FEEDS: set[str] = {"threatfox"}


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

    if feed.slug in _TEMP_DISABLED_FEEDS:
        raise HTTPException(
            status_code=503,
            detail=f"Feed '{feed.slug}' is temporarily disabled.",
        )

    background_tasks.add_task(run_feed_sync, feed_id=feed_id, feed_slug=feed.slug, connector_path=connector_path)

    return {
        "status": "sync_started",
        "feed_id": str(feed_id),
        "feed_name": feed.name,
        "message": f"Sync for {feed.name} is running in the background.",
    }


async def _run_sync_all_background(
    force: bool,
    feed_slug: str,
    enrich: bool,
    enrich_limit: int
):
    """Background task that performs feed sync and enrichment."""
    from datetime import datetime
    from sqlalchemy import select
    from sqlalchemy.orm import selectinload
    from app.models.enrichment import Enrichment
    from app.models.ioc import IOC
    from app.services.enrichment_engine import enrich_ioc
    from app.database import AsyncSessionLocal
    
    async with AsyncSessionLocal() as db:
        start_time = datetime.utcnow()
        
        # ═══════════════════════════════════════════════════════════════════════
        # STEP 1: FEED SYNCHRONIZATION
        # ═══════════════════════════════════════════════════════════════════════
        logger.info("background_cron_started", step="feed_sync", force=force, feed_slug=feed_slug)
        
        # Build query - filter by slug if specified
        query = select(FeedSource).where(FeedSource.is_enabled == True)  # noqa: E712
        if feed_slug:
            query = query.where(FeedSource.slug == feed_slug)
        
        result = await db.execute(query)
        feeds = result.scalars().all()
        
        if feed_slug and not feeds:
            logger.error("background_cron_feed_not_found", slug=feed_slug)
            return
        
        now = datetime.utcnow()
        synced_results = []
        skipped_count = 0
        
        for feed in feeds:
            # Skip temporarily disabled feeds
            if feed.slug in _TEMP_DISABLED_FEEDS:
                logger.info("background_sync_skipped_temp_disabled", slug=feed.slug)
                skipped_count += 1
                continue

            # Check if feed should be synced
            if not force:
                # Only sync if overdue (smart mode)
                freq = feed.sync_frequency or 3600  # default 1 hour
                last = feed.last_sync_at
                overdue = last is None or (now - last).total_seconds() >= freq
                
                if not overdue:
                    skipped_count += 1
                    continue
            # If force=True, skip the overdue check and sync all feeds
                
            connector_path = FEED_CONNECTORS.get(feed.slug)
            if not connector_path:
                logger.warning("background_sync_no_connector", slug=feed.slug)
                synced_results.append({
                    "feed_id": str(feed.id),
                    "name": feed.name,
                    "slug": feed.slug,
                    "status": "error",
                    "message": "No connector registered"
                })
                continue
            
            # Sync synchronously (blocking)
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
                
                logger.info("background_sync_success", feed=feed.slug, forced=force)
                
            except Exception as e:
                logger.error("background_sync_failed", feed=feed.slug, error=str(e))
                synced_results.append({
                    "feed_id": str(feed.id),
                    "name": feed.name,
                    "slug": feed.slug,
                    "status": "failed",
                    "error": str(e)
                })
        
        synced_count = len([r for r in synced_results if r.get("status") == "success"])
        failed_count = len([r for r in synced_results if r.get("status") == "failed"])
        
        feed_sync_duration = (datetime.utcnow() - start_time).total_seconds()
        logger.info("background_feed_sync_completed", 
                    synced=synced_count, 
                    failed=failed_count,
                    skipped=skipped_count,
                    duration_sec=feed_sync_duration)
        
        # ═══════════════════════════════════════════════════════════════════════
        # STEP 2: ENRICHMENT
        # ═══════════════════════════════════════════════════════════════════════
        if enrich:
            enrich_start = datetime.utcnow()
            logger.info("background_enrichment_started", limit=enrich_limit)
            
            # Find IOCs without enrichment (up to limit)
            no_enrichment_query = (
                select(IOC)
                .options(selectinload(IOC.enrichments))
                .outerjoin(Enrichment, IOC.id == Enrichment.ioc_id)
                .where(Enrichment.id.is_(None))
                .limit(enrich_limit)
            )
            result = await db.execute(no_enrichment_query)
            iocs_to_enrich = result.scalars().all()
            
            logger.info("found_unenriched_iocs", count=len(iocs_to_enrich))
            
            # Enrich each IOC synchronously
            enriched = 0
            failed = 0
            
            for ioc in iocs_to_enrich:
                try:
                    await enrich_ioc(db, ioc)
                    await db.flush()
                    enriched += 1
                    
                    if enriched % 10 == 0:
                        logger.info("background_enrichment_progress", 
                                   enriched=enriched, 
                                   total=len(iocs_to_enrich))
                                   
                except Exception as e:
                    failed += 1
                    logger.warning("background_enrichment_failed", 
                                  ioc_id=str(ioc.id), 
                                  ioc_value=ioc.value,
                                  error=str(e))
            
            enrichment_duration = (datetime.utcnow() - enrich_start).total_seconds()
            
            logger.info("background_enrichment_completed", 
                       enriched=enriched, 
                       failed=failed,
                       duration_sec=enrichment_duration)
        
        total_duration = (datetime.utcnow() - start_time).total_seconds()
        logger.info("background_cron_completed",
                   total_duration_sec=round(total_duration, 2),
                   synced_feeds=synced_count,
                   enriched_iocs=enriched if enrich else 0)


@router.post("/sync-all", status_code=202)
async def sync_all_feeds(
    background_tasks: BackgroundTasks,
    db: AsyncSession = Depends(get_db),
    force: bool = Query(False, description="Force sync all feeds (ignore sync_frequency)"),
    feed_slug: str = Query(None, description="Sync only specific feed by slug (e.g., 'threatfox')"),
    enrich: bool = Query(True, description="Auto-enrich unenriched IOCs after feed sync"),
    enrich_limit: int = Query(100, description="Max IOCs to enrich", ge=1, le=500)
):
    """
    🔄 UNIFIED DAILY CRON JOB - Sync feeds + Enrich IOCs (Background)
    
    This endpoint queues ALL background maintenance and returns immediately:
    
    STEP 1: Feed Synchronization (runs in background)
    - If force=False: Syncs only overdue feeds based on sync_frequency
    - If force=True: Syncs ALL enabled feeds regardless of last sync time
    - If feed_slug provided: Syncs ONLY that specific feed (e.g., 'threatfox')
    - Each feed completes fully before next feed starts (no parallel processing)
    
    STEP 2: Enrichment (runs in background if enrich=True)
    - Finds IOCs without enrichment data or with expired enrichments
    - Enriches up to enrich_limit IOCs (default: 100)
    
    ⚠️ Returns 202 Accepted immediately - actual work runs in background
    
    Usage Examples:
    - Sync all feeds: POST /api/v1/feeds/sync-all?force=true
    - Sync only ThreatFox: POST /api/v1/feeds/sync-all?feed_slug=threatfox
    - Sync ThreatFox without enrichment: POST /api/v1/feeds/sync-all?feed_slug=threadfox&enrich=false
    
    Vercel Cron:
    {
      "crons": [{
        "path": "/api/v1/feeds/sync-all?force=true&enrich=true&enrich_limit=100",
        "schedule": "0 0 * * *"
      }]
    }
    """
    from datetime import datetime
    from sqlalchemy import select
    
    # Validate feed_slug if provided
    if feed_slug:
        query = select(FeedSource).where(
            FeedSource.slug == feed_slug,
            FeedSource.is_enabled == True  # noqa: E712
        )
        result = await db.execute(query)
        feed = result.scalar_one_or_none()
        if not feed:
            raise HTTPException(
                status_code=404,
                detail=f"Feed with slug '{feed_slug}' not found or disabled"
            )
    
    # Queue the background task - returns immediately
    background_tasks.add_task(
        _run_sync_all_background,
        force=force,
        feed_slug=feed_slug,
        enrich=enrich,
        enrich_limit=enrich_limit
    )
    
    logger.info("sync_all_queued",
               force=force,
               feed_slug=feed_slug,
               enrich=enrich,
               enrich_limit=enrich_limit)
    
    return {
        "status": "queued",
        "message": "Feed synchronization and enrichment has been queued and will run in the background",
        "parameters": {
            "force": force,
            "feed_slug": feed_slug or "all",
            "enrich": enrich,
            "enrich_limit": enrich_limit if enrich else 0
        },
        "note": "Check server logs for progress and results"
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
