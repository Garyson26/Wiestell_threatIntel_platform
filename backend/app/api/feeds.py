"""Feed management API endpoints."""

import importlib
import os
from datetime import datetime, timezone

from fastapi import APIRouter, BackgroundTasks, Depends, HTTPException
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

import structlog
from app.database import AsyncSessionLocal, get_db
from app.models.feed import FeedSource
from app.schemas.feed import FeedCreate, FeedUpdate, FeedResponse
from app.services.feed_ingestion import ingest_iocs

logger = structlog.get_logger()

# Registry mapping feed slug -> connector class path
# Includes aliases for slugs that may differ between DB records and canonical names
FEED_CONNECTORS = {
    "urlhaus": "app.feeds.urlhaus.URLhausFeed",
    "urlhaus-feed": "app.feeds.urlhaus.URLhausFeed",
    "threatfox": "app.feeds.threatfox.ThreatFoxFeed",
    "malwarebazaar": "app.feeds.malwarebazaar.MalwareBazaarFeed",
    "blocklist-de": "app.feeds.blocklist_de.BlocklistDeFeed",
    "emerging-threats": "app.feeds.emergingthreats.EmergingThreatsFeed",
    "emerging-threats-feed": "app.feeds.emergingthreats.EmergingThreatsFeed",
    "feodo-tracker": "app.feeds.feodo_tracker.FeodoTrackerFeed",
    "feodo-tracker-feed": "app.feeds.feodo_tracker.FeodoTrackerFeed",
    "otx-alienvault": "app.feeds.otx_alienvault.OTXAlienVaultFeed",
    "abuseipdb": "app.feeds.abuseipdb.AbuseIPDBFeed",
    "phishtank": "app.feeds.phishtank.PhishTankFeed",
    "virustotal": "app.feeds.virustotal.VirusTotalFeed",
    "mitre-attack": "app.feeds.mitre_attack.MitreAttackFeed",
}

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

    background_tasks.add_task(_run_feed_sync, feed_id=feed_id, feed_slug=feed.slug, connector_path=connector_path)

    return {
        "status": "sync_started",
        "feed_id": str(feed_id),
        "feed_name": feed.name,
        "message": f"Sync for {feed.name} is running in the background.",
    }


async def _run_feed_sync(feed_id: str, feed_slug: str, connector_path: str) -> None:
    """Background task: fetch IOCs from the connector and ingest into the DB."""
    module_path, class_name = connector_path.rsplit(".", 1)
    import importlib as _imp
    module = _imp.import_module(module_path)
    connector_class = getattr(module, class_name)

    api_key = None
    # Resolve API key from environment if the feed requires one
    async with AsyncSessionLocal() as session:
        result = await session.execute(select(FeedSource).where(FeedSource.id == feed_id))
        feed = result.scalar_one_or_none()
        if not feed:
            logger.error("background_sync_feed_not_found", feed_id=feed_id)
            return
        if feed.api_key_env:
            api_key = os.environ.get(feed.api_key_env)

    connector = connector_class(api_key=api_key)

    try:
        iocs = await connector.run()
    except Exception as e:
        logger.error("background_sync_fetch_error", feed=feed_slug, error=str(e))
        async with AsyncSessionLocal() as session:
            result = await session.execute(select(FeedSource).where(FeedSource.id == feed_id))
            feed = result.scalar_one_or_none()
            if feed:
                feed.last_sync_at = datetime.now(timezone.utc).replace(tzinfo=None)
                feed.last_sync_status = "failed"
                await session.commit()
        return

    async with AsyncSessionLocal() as session:
        result = await session.execute(select(FeedSource).where(FeedSource.id == feed_id))
        feed = result.scalar_one_or_none()
        if not feed:
            return
        try:
            count = await ingest_iocs(session, feed, iocs)
            await session.commit()
            logger.info("background_sync_complete", feed=feed_slug, iocs_ingested=count)
        except Exception as e:
            await session.rollback()
            logger.error("background_sync_ingest_error", feed=feed_slug, error=str(e))


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
                "timestamp": feed.last_sync_at.isoformat() if feed.last_sync_at else None,
                "status": feed.last_sync_status or "never_synced",
                "iocs_ingested": feed.ioc_count,
            }
        ],
    }
