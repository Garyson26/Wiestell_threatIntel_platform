"""Celery tasks for feed ingestion."""

import asyncio
import importlib
import os
from datetime import datetime, timezone
from typing import Optional

import structlog
from app.tasks.celery_app import celery_app
from app.database import SyncSessionLocal
from app.models.feed import FeedSource
from app.services.feed_ingestion import ingest_iocs

logger = structlog.get_logger()


def _now() -> datetime:
    return datetime.now(timezone.utc).replace(tzinfo=None)


def _mark_feed_failed(feed_slug: str, error: str) -> None:
    """Write last_sync_status='failed' and last_sync_error to the feed row."""
    session = SyncSessionLocal()
    try:
        feed = session.query(FeedSource).filter(FeedSource.slug == feed_slug).first()
        if feed:
            feed.last_sync_at = _now()
            feed.last_sync_status = "failed"
            feed.last_sync_error = error
            session.commit()
    except Exception:
        session.rollback()
    finally:
        session.close()


def _mark_feed_no_data(feed_slug: str) -> None:
    """Write last_sync_status='no_data' to the feed row."""
    session = SyncSessionLocal()
    try:
        feed = session.query(FeedSource).filter(FeedSource.slug == feed_slug).first()
        if feed:
            feed.last_sync_at = _now()
            feed.last_sync_status = "no_data"
            feed.last_sync_error = None
            session.commit()
    except Exception:
        session.rollback()
    finally:
        session.close()

# Feed connector registry
FEED_CONNECTORS = {
    "urlhaus": "app.feeds.urlhaus.URLhausFeed",
    "threatfox": "app.feeds.threatfox.ThreatFoxFeed",
    "malwarebazaar": "app.feeds.malwarebazaar.MalwareBazaarFeed",
    "blocklist-de": "app.feeds.blocklist_de.BlocklistDeFeed",
    "emerging-threats": "app.feeds.emergingthreats.EmergingThreatsFeed",
    "feodo-tracker": "app.feeds.feodo_tracker.FeodoTrackerFeed",
    "otx-alienvault": "app.feeds.otx_alienvault.OTXAlienVaultFeed",
    "abuseipdb": "app.feeds.abuseipdb.AbuseIPDBFeed",
    # "phishtank" and "virustotal" removed 2026-07-29 with their connector
    # modules. This registry is a duplicate of the authoritative one in
    # services/feed_scheduler.py and is only reachable through the Celery beat
    # schedule, which is entirely commented out.
}


def _get_feed_connector(slug: str, api_key: Optional[str] = None):
    """Dynamically import and instantiate a feed connector."""
    connector_path = FEED_CONNECTORS.get(slug)
    if not connector_path:
        return None

    module_path, class_name = connector_path.rsplit(".", 1)
    module = importlib.import_module(module_path)
    connector_class = getattr(module, class_name)
    return connector_class(api_key=api_key)


@celery_app.task(bind=True, name="app.tasks.feed_tasks.sync_feed")
def sync_feed(self, feed_slug: str, api_key: Optional[str] = None):
    """Sync a single feed by slug."""
    logger.info("sync_feed_start", feed=feed_slug)

    connector = _get_feed_connector(feed_slug, api_key)
    if not connector:
        logger.error("unknown_feed_connector", slug=feed_slug)
        return {"status": "error", "message": f"Unknown feed: {feed_slug}"}

    # ── Fetch phase ────────────────────────────────────────────────────────
    try:
        loop = asyncio.new_event_loop()
        try:
            iocs = loop.run_until_complete(connector.run())
        finally:
            loop.close()
    except Exception as e:
        logger.error("sync_feed_fetch_error", feed=feed_slug, error=str(e))
        _mark_feed_failed(feed_slug, str(e))
        return {"status": "error", "message": str(e)}

    if not iocs:
        logger.info("feed_no_iocs", feed=feed_slug)
        _mark_feed_no_data(feed_slug)
        return {"status": "success", "iocs_ingested": 0}

    # ── Ingest phase ───────────────────────────────────────────────────────
    # Drives the ASYNC ingestion path. The synchronous mirror this used to call
    # (`ingest_iocs_sync`) was deleted on 2026-07-31: it was unreachable in
    # production and had drifted from the async copy twice in one change set. Rather
    # than maintain two implementations of the ingest chunking, retry and scoring
    # logic, this Celery entry point runs the single implementation in its own event
    # loop — the same shape the fetch phase above already uses.
    try:
        count = asyncio.run(_ingest_async(feed_slug, iocs))
    except Exception as e:
        logger.error("feed_ingestion_db_error", feed=feed_slug, error=str(e))
        _mark_feed_failed(feed_slug, str(e))
        return {"status": "error", "message": str(e)}

    if count is None:
        logger.error("feed_not_found", slug=feed_slug)
        return {"status": "error", "message": "Feed not found in DB"}

    logger.info("sync_feed_complete", feed=feed_slug, count=count)
    return {"status": "success", "iocs_ingested": count}


async def _ingest_async(feed_slug: str, iocs: list) -> Optional[int]:
    """Ingest via the async path, in a fresh async session.

    Returns the ingested count, or None if the feed row is missing.
    """
    from sqlalchemy import select

    from app.database import AsyncSessionLocal

    async with AsyncSessionLocal() as session:
        result = await session.execute(
            select(FeedSource).where(FeedSource.slug == feed_slug)
        )
        feed = result.scalar_one_or_none()
        if not feed:
            return None
        # ingest_iocs commits per chunk internally; the trailing commit persists
        # the final status update it makes to the feed row.
        count = await ingest_iocs(session, feed, iocs)
        await session.commit()
        return count


# Seconds between each feed dispatch to avoid running all feeds simultaneously
FEED_STAGGER_INTERVAL = 30


@celery_app.task(name="app.tasks.feed_tasks.sync_all_feeds")
def sync_all_feeds():
    """Sync all enabled feeds, staggered to avoid running all at once."""
    session = SyncSessionLocal()
    try:
        feeds = session.query(FeedSource).filter(FeedSource.is_enabled == True).all()
        results = []
        for index, feed in enumerate(feeds):
            api_key = None
            if feed.api_key_env:
                api_key = os.environ.get(feed.api_key_env)
            countdown = index * FEED_STAGGER_INTERVAL
            result = sync_feed.apply_async(args=[feed.slug, api_key], countdown=countdown)
            results.append({"feed": feed.slug, "task_id": str(result.id), "starts_in_seconds": countdown})
        return results
    finally:
        session.close()


@celery_app.task(name="app.tasks.feed_tasks.sync_critical_feeds")
def sync_critical_feeds():
    """Sync high-priority feeds more frequently, staggered to avoid overlap."""
    critical_slugs = ["feodo-tracker", "urlhaus", "threatfox"]
    results = []
    session = SyncSessionLocal()
    try:
        for index, slug in enumerate(critical_slugs):
            api_key = None
            feed = session.query(FeedSource).filter(FeedSource.slug == slug).first()
            if feed and feed.api_key_env:
                api_key = os.environ.get(feed.api_key_env)
            countdown = index * FEED_STAGGER_INTERVAL
            result = sync_feed.apply_async(args=[slug, api_key], countdown=countdown)
            results.append({"feed": slug, "task_id": str(result.id), "starts_in_seconds": countdown})
    finally:
        session.close()
    return results
