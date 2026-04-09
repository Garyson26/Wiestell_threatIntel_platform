"""Cron endpoints for Vercel Cron Jobs to trigger scheduled tasks."""

import asyncio
from fastapi import APIRouter, Depends, Request, HTTPException
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

import structlog
from app.database import get_db
from app.models.feed import FeedSource
from app.services.feed_scheduler import FEED_CONNECTORS, run_feed_sync

logger = structlog.get_logger()

router = APIRouter()


def verify_cron_secret(request: Request):
    """Verify the request is from Vercel Cron (optional security)."""
    # Vercel Cron sends a secret header that you can verify
    # For now, we'll allow any request. In production, add:
    # auth_header = request.headers.get("Authorization")
    # if auth_header != f"Bearer {settings.CRON_SECRET}":
    #     raise HTTPException(status_code=401, detail="Unauthorized")
    pass


@router.post("/sync-all-feeds")
async def cron_sync_all_feeds(
    db: AsyncSession = Depends(get_db),
    _verified: None = Depends(verify_cron_secret)
):
    """
    Cron endpoint: Sync all enabled feeds.
    
    This endpoint is designed to be called by Vercel Cron Jobs.
    It triggers a sync for all enabled feeds without waiting for completion.
    
    Configure in vercel.json:
    "crons": [
      {
        "path": "/api/v1/cron/sync-all-feeds",
        "schedule": "0 * * * *"
      }
    ]
    """
    logger.info("cron_sync_all_feeds_triggered")
    
    # Get all enabled feeds
    result = await db.execute(
        select(FeedSource).where(FeedSource.is_enabled == True)  # noqa: E712
    )
    feeds = result.scalars().all()
    
    synced_feeds = []
    skipped_feeds = []
    
    for feed in feeds:
        connector_path = FEED_CONNECTORS.get(feed.slug)
        if not connector_path:
            logger.warning("cron_no_connector", slug=feed.slug)
            skipped_feeds.append({
                "feed_id": str(feed.id),
                "name": feed.name,
                "reason": "no_connector"
            })
            continue
        
        # Start sync in background (fire and forget)
        asyncio.create_task(
            run_feed_sync(
                feed_id=str(feed.id),
                feed_slug=feed.slug,
                connector_path=connector_path
            )
        )
        
        synced_feeds.append({
            "feed_id": str(feed.id),
            "name": feed.name,
            "slug": feed.slug
        })
        logger.info("cron_feed_sync_started", feed=feed.slug)
    
    return {
        "status": "success",
        "message": f"Started sync for {len(synced_feeds)} feeds",
        "synced": synced_feeds,
        "skipped": skipped_feeds,
        "total_enabled": len(feeds)
    }


@router.get("/health")
async def cron_health():
    """Health check for cron service."""
    return {
        "status": "healthy",
        "service": "cron-scheduler",
        "message": "Cron endpoints are ready"
    }
