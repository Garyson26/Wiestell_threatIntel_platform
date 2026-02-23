"""Celery tasks for feed ingestion."""

import asyncio
from typing import Optional

import structlog
from app.tasks.celery_app import celery_app
from app.database import SyncSessionLocal
from app.models.feed import FeedSource
from app.services.feed_ingestion import ingest_iocs_sync

logger = structlog.get_logger()

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
    "phishtank": "app.feeds.phishtank.PhishTankFeed",
    "virustotal": "app.feeds.virustotal.VirusTotalFeed",
}


def _get_feed_connector(slug: str, api_key: Optional[str] = None):
    """Dynamically import and instantiate a feed connector."""
    connector_path = FEED_CONNECTORS.get(slug)
    if not connector_path:
        return None

    module_path, class_name = connector_path.rsplit(".", 1)
    import importlib
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

    try:
        # Run the async feed connector in a sync context
        loop = asyncio.new_event_loop()
        iocs = loop.run_until_complete(connector.run())
        loop.close()

        if not iocs:
            logger.info("feed_no_iocs", feed=feed_slug)
            return {"status": "success", "iocs_ingested": 0}

        session = SyncSessionLocal()
        try:
            feed = session.query(FeedSource).filter(FeedSource.slug == feed_slug).first()
            if not feed:
                logger.error("feed_not_found", slug=feed_slug)
                return {"status": "error", "message": "Feed not found in DB"}

            count = ingest_iocs_sync(session, feed, iocs)
            session.commit()

            logger.info("sync_feed_complete", feed=feed_slug, count=count)
            return {"status": "success", "iocs_ingested": count}

        except Exception as e:
            session.rollback()
            logger.error("feed_ingestion_db_error", feed=feed_slug, error=str(e))
            return {"status": "error", "message": str(e)}
        finally:
            session.close()

    except Exception as e:
        logger.error("sync_feed_error", feed=feed_slug, error=str(e))
        return {"status": "error", "message": str(e)}


@celery_app.task(name="app.tasks.feed_tasks.sync_all_feeds")
def sync_all_feeds():
    """Sync all enabled feeds."""
    session = SyncSessionLocal()
    try:
        feeds = session.query(FeedSource).filter(FeedSource.is_enabled == True).all()
        results = []
        for feed in feeds:
            api_key = None
            if feed.api_key_env:
                import os
                api_key = os.environ.get(feed.api_key_env)
            result = sync_feed.delay(feed.slug, api_key)
            results.append({"feed": feed.slug, "task_id": str(result.id)})
        return results
    finally:
        session.close()


@celery_app.task(name="app.tasks.feed_tasks.sync_critical_feeds")
def sync_critical_feeds():
    """Sync high-priority feeds more frequently."""
    critical_slugs = ["feodo-tracker", "urlhaus", "threatfox"]
    results = []
    for slug in critical_slugs:
        result = sync_feed.delay(slug)
        results.append({"feed": slug, "task_id": str(result.id)})
    return results
