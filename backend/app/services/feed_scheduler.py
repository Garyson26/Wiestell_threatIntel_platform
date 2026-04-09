"""
Periodic feed scheduler (no Redis/Celery required).

At startup the scheduler is started as a background asyncio Task.
Every _POLL_INTERVAL seconds it checks every enabled feed's last_sync_at
against its sync_frequency and fires a sync for any overdue feed.
A running-set prevents duplicate concurrent syncs for the same feed.
"""

import asyncio
import importlib
import os
from datetime import datetime, timezone
from typing import Optional

import structlog
from sqlalchemy import select
from sqlalchemy.exc import OperationalError

from app.database import AsyncSessionLocal
from app.models.feed import FeedSource
from app.services.feed_ingestion import ingest_iocs
from app.config import settings

logger = structlog.get_logger()

# Semaphore: at most 5 feed syncs run concurrently to avoid pool exhaustion
_SYNC_SEMAPHORE = asyncio.Semaphore(5)

# ── Registry ─────────────────────────────────────────────────────────────────
# Canonical map from DB slug → dotted connector class path.
# Add DB-slug aliases so that rows named "urlhaus-feed" etc. still resolve.
FEED_CONNECTORS: dict[str, str] = {
    "urlhaus": "app.feeds.urlhaus.URLhausFeed",
    "urlhaus-feed": "app.feeds.urlhaus.URLhausFeed",
    "threatfox": "app.feeds.threatfox.ThreatFoxFeed",
    "malwarebazaar": "app.feeds.malwarebazaar.MalwareBazaarFeed",
    "malwarebazaar-feed": "app.feeds.malwarebazaar.MalwareBazaarFeed",
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

# ── Constants ─────────────────────────────────────────────────────────────────
_POLL_INTERVAL = 60  # seconds between scheduler ticks

# Feed IDs that are currently syncing — prevents duplicate concurrent runs
_running: set[str] = set()


# ── Core sync function (used by scheduler AND manual trigger endpoint) ────────

async def run_feed_sync(feed_id: str, feed_slug: str, connector_path: str) -> None:
    """Fetch IOCs from a connector and ingest them into the DB.

    - Resolves the API key from environment variables automatically.
    - Retries up to 3 times on transient MySQL OperationalError.
    - Acquires a semaphore slot so at most 5 syncs run concurrently.
    - Updates last_sync_at / last_sync_status on the feed row when done.
    """
    async with _SYNC_SEMAPHORE:
        await _run_feed_sync_inner(feed_id, feed_slug, connector_path)


async def _run_feed_sync_inner(feed_id: str, feed_slug: str, connector_path: str) -> None:
    """Internal implementation; called under the semaphore."""
    module_path, class_name = connector_path.rsplit(".", 1)
    module = importlib.import_module(module_path)
    connector_class = getattr(module, class_name)

    # Resolve API key and release the connection before the (potentially slow) HTTP fetch.
    api_key: Optional[str] = None
    async with AsyncSessionLocal() as session:
        result = await session.execute(select(FeedSource).where(FeedSource.id == feed_id))
        feed = result.scalar_one_or_none()
        if not feed:
            logger.error("run_feed_sync_not_found", feed_id=feed_id)
            return
        if feed.api_key_env:
            api_key = os.environ.get(feed.api_key_env) or getattr(settings, feed.api_key_env, None)
        # session closes here — connection returned to pool before HTTP fetch

    connector = connector_class(api_key=api_key)

    # Fetch (no DB connection held during network I/O)
    try:
        iocs = await connector.run()
    except Exception as exc:
        logger.error("run_feed_sync_fetch_error", feed=feed_slug, error=str(exc))
        async with AsyncSessionLocal() as session:
            result = await session.execute(select(FeedSource).where(FeedSource.id == feed_id))
            feed = result.scalar_one_or_none()
            if feed:
                feed.last_sync_at = datetime.utcnow()
                feed.last_sync_status = "failed"
                feed.last_sync_error = str(exc)
                await session.commit()
        return

    # Ingest — fresh session per attempt; ingest_iocs commits in chunks internally
    _MAX_RETRIES = 3
    # ThreatFox has ~57k IOCs; use larger batch size to complete within timeout
    batch_size = 500 if feed_slug == "threatfox" else 15
    
    for attempt in range(1, _MAX_RETRIES + 1):
        async with AsyncSessionLocal() as session:
            result = await session.execute(select(FeedSource).where(FeedSource.id == feed_id))
            feed = result.scalar_one_or_none()
            if not feed:
                return
            try:
                count = await ingest_iocs(session, feed, iocs, batch_size=batch_size)
                # ingest_iocs already sets last_sync_status, last_sync_at, and ioc_count
                feed.last_sync_error = None  # Clear any previous error
                await session.commit()
                logger.info("run_feed_sync_complete", feed=feed_slug, iocs_ingested=count)
                return  # success — exit retry loop
            except OperationalError as exc:
                await session.rollback()
                if attempt < _MAX_RETRIES:
                    wait = 2 ** attempt  # exponential backoff: 2s, 4s
                    logger.warning(
                        "run_feed_sync_retrying",
                        feed=feed_slug,
                        attempt=attempt,
                        wait=wait,
                        error=str(exc),
                    )
                    await asyncio.sleep(wait)
                else:
                    logger.error("run_feed_sync_ingest_error", feed=feed_slug, error=str(exc))
                    await _mark_failed(feed_id, str(exc))
            except Exception as exc:
                await session.rollback()
                logger.error("run_feed_sync_ingest_error", feed=feed_slug, error=str(exc))
                await _mark_failed(feed_id, str(exc))
                return


async def _mark_failed(feed_id: str, error: str) -> None:
    """Persist a 'failed' status on the feed row in a fresh session."""
    async with AsyncSessionLocal() as session:
        result = await session.execute(select(FeedSource).where(FeedSource.id == feed_id))
        feed = result.scalar_one_or_none()
        if feed:
            feed.last_sync_at = datetime.utcnow()
            feed.last_sync_status = "failed"
            feed.last_sync_error = error
            await session.commit()


# ── Scheduler loop ────────────────────────────────────────────────────────────

async def _sync_and_release(feed_id: str, feed_slug: str, connector_path: str) -> None:
    """Wrapper that removes feed_id from _running after sync completes."""
    try:
        await run_feed_sync(feed_id=feed_id, feed_slug=feed_slug, connector_path=connector_path)
    finally:
        _running.discard(feed_id)


async def _tick() -> None:
    """One scheduler tick: find overdue feeds and schedule them."""
    now = datetime.utcnow()
    async with AsyncSessionLocal() as session:
        result = await session.execute(
            select(FeedSource).where(FeedSource.is_enabled == True)  # noqa: E712
        )
        feeds = result.scalars().all()

    for feed in feeds:
        if feed.id in _running:
            continue  # already syncing, skip

        freq = feed.sync_frequency or 3600
        last = feed.last_sync_at  # naive UTC from MySQL, or None
        overdue = last is None or (now - last).total_seconds() >= freq

        if overdue:
            connector_path = FEED_CONNECTORS.get(feed.slug)
            if not connector_path:
                logger.warning("scheduler_no_connector", slug=feed.slug)
                continue

            logger.info("scheduler_triggering_sync", feed=feed.slug, freq=freq)
            _running.add(feed.id)
            asyncio.create_task(
                _sync_and_release(str(feed.id), feed.slug, connector_path)
            )


async def feed_scheduler_loop() -> None:
    """Main loop. Runs forever; cancelled cleanly on app shutdown."""
    from app.database import async_engine

    logger.info("feed_scheduler_started", poll_interval=_POLL_INTERVAL)
    while True:
        try:
            await _tick()
        except Exception as exc:
            error_str = str(exc)
            logger.error("feed_scheduler_tick_error", error=error_str)
            # If the error is a dead TCP transport (aiomysql connection closed by
            # the server while sitting in the pool), dispose the entire pool so
            # all stale connections are evicted. The next tick will open fresh ones.
            if "TCPTransport" in error_str or "handler is closed" in error_str or "Lost connection" in error_str:
                logger.warning("feed_scheduler_pool_reset", reason="stale_connections_detected")
                await async_engine.dispose()
        await asyncio.sleep(_POLL_INTERVAL)
