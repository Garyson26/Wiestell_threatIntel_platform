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
from app.config import ALLOWED_FEED_API_KEY_ENVS, settings
from app.utils.sanitize import redact_secrets

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
    # NOTE: "phishtank" and "virustotal" were removed on 2026-07-29 along with
    # their connector modules. Their `feed_sources` rows are *not* deleted — they
    # are soft-disabled via `is_enabled` (revision e5f6a7b80002), because
    # `ioc_sources` still links them to indicators they contributed and deleting
    # the rows would silently lower `source_count`, and therefore the
    # source-diversity term, for every one of those indicators.
    # NOTE: there is deliberately no "mitre-attack" entry. app/feeds/mitre_attack.py
    # exposes a module-level load_attack_data() loader used by scripts/seed_mitre.py
    # to populate attack_techniques — it is not a BaseFeed connector and produces no
    # IOCs. The previous entry pointed at a non-existent MitreAttackFeed class, so any
    # sync of a feed row with that slug failed with AttributeError.
    # Vulnerability feeds (CVE IOCs)
    "cisa-kev": "app.feeds.cisa_kev.CISAKEVFeed",
    "cisa-kev-feed": "app.feeds.cisa_kev.CISAKEVFeed",
    "ecrimelabs-metasploit": "app.feeds.ecrimelabs.ECrimeLabsCVEFeed",
    "ecrimelabs": "app.feeds.ecrimelabs.ECrimeLabsCVEFeed",
    # Government incident-response hashes
    "misp-cert-fr": "app.feeds.misp_cert_fr.MISPCertFRFeed",
    "cert-fr": "app.feeds.misp_cert_fr.MISPCertFRFeed",
}

# ── Constants ─────────────────────────────────────────────────────────────────
_POLL_INTERVAL = 60  # seconds between scheduler ticks

# Exponential back-off ceiling (Spec 2 §4.6). Three days, so a feed that has been dead
# for a week is still retried twice a week rather than never — the point is to stop a
# broken feed consuming a slot in EVERY window, not to give up on it.
_BACKOFF_CAP_SECONDS = 3 * 24 * 3600

# `2 ** n` is exact for arbitrarily large n in Python, so a feed with 5,000 consecutive
# failures would compute a 1,500-digit integer before `min()` discarded it. Clamping the
# exponent keeps the arithmetic bounded; 2**32 * any sane interval is already far past
# the cap, so this changes no reachable outcome.
_BACKOFF_MAX_EXPONENT = 32


def _effective_interval(sync_frequency: int, consecutive_failures: int) -> int:
    """The interval this feed must actually wait, including back-off.

    ``sync_frequency * 2 ** consecutive_failures``, capped at three days.

    WHY BACK-OFF AT ALL. Without it a permanently broken feed is retried on every tick
    forever: it holds one of the five concurrent sync slots, burns a connection from a
    pool sized for a shared host, and writes a `failed` row every window. One dead feed
    degrades the others. With it, a feed failing at a 1-hour cadence is retried after
    1h, 2h, 4h, 8h ... and settles at the 3-day cap.

    COMPUTED FROM ``last_attempt_at``, not ``last_sync_at`` — the caller passes the
    former. That matters specifically here: a failing feed's ``last_sync_at`` is frozen
    at its last SUCCESS (Section A), which may be weeks ago, so measuring back-off from
    it would make every retry instantly due and the back-off would do nothing at all.
    """
    if consecutive_failures <= 0:
        return sync_frequency
    exponent = min(consecutive_failures, _BACKOFF_MAX_EXPONENT)
    backed_off = min(sync_frequency * (2 ** exponent), _BACKOFF_CAP_SECONDS)
    # THE CAP IS A CEILING ON THE BACK-OFF, NOT ON THE INTERVAL. Without this `max`, a
    # feed whose own cadence exceeds three days (a hand-configured weekly feed) would be
    # capped BELOW its base interval, so failing would make it retry MORE often than
    # working. Caught by its own test rather than by review.
    return max(sync_frequency, backed_off)

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

    # CAPTURED BEFORE THE FETCH, and this ordering is the Phase 4 cadence fix.
    #
    # Next-due is computed as `last_attempt_at + sync_frequency`. If that timestamp were
    # taken at completion, every interval would silently become
    # `sync_frequency + sync_duration` and drift further on each cycle — a feed set to 6h
    # against a 6h cron would never fire on schedule, because by the time the next tick
    # arrives it is always a few minutes short of due. Taking it at the start makes the
    # interval exact for every value of sync_frequency, including sync_frequency ==
    # cron_interval. See the design notes §1.3.
    attempt_started_at = datetime.now(timezone.utc).replace(tzinfo=None)

    # Resolve API key and release the connection before the (potentially slow) HTTP fetch.
    api_key: Optional[str] = None
    stored_cursor: Optional[str] = None
    stored_etag: Optional[str] = None
    stored_last_modified: Optional[str] = None
    async with AsyncSessionLocal() as session:
        result = await session.execute(select(FeedSource).where(FeedSource.id == feed_id))
        feed = result.scalar_one_or_none()
        if not feed:
            logger.error("run_feed_sync_not_found", feed_id=feed_id)
            return

        # Stamped here, in the same session that resolves the key, so it is committed
        # BEFORE the fetch begins. If it were written only at the end, a sync that
        # crashes the process — or is killed by a Render spin-down mid-fetch — would
        # leave the feed looking un-attempted and it would be retried immediately on
        # every subsequent tick. Written on every attempt, success or failure.
        stored_cursor = feed.sync_cursor
        stored_etag = feed.http_etag
        stored_last_modified = feed.http_last_modified
        feed.last_attempt_at = attempt_started_at
        await session.commit()
        if feed.api_key_env:
            # Only feed-key variables may be dereferenced. Without this check a
            # feed row pointing at SECRET_KEY / DATABASE_URL / RESEND_API_KEY
            # would have that value forwarded to a third-party endpoint as an
            # API key. Enforced here as well as in the schema so pre-existing
            # rows cannot exfiltrate secrets.
            if feed.api_key_env in ALLOWED_FEED_API_KEY_ENVS:
                api_key = os.environ.get(feed.api_key_env) or getattr(
                    settings, feed.api_key_env, None
                )
            else:
                logger.error(
                    "feed_api_key_env_rejected",
                    feed=feed_slug,
                    api_key_env=feed.api_key_env,
                )
        # session closes here — connection returned to pool before HTTP fetch

    connector = connector_class(api_key=api_key)
    # Hand the connector the position the last SUCCESSFUL sync reached. Read in the
    # session above alongside the API key, so no extra round-trip. A connector that does
    # not use a cursor simply ignores it.
    connector.sync_cursor = stored_cursor
    # Conditional-request validators from the last successful fetch (D3). A connector
    # whose server ignores them simply gets a 200, exactly as before.
    connector.http_etag = stored_etag
    connector.http_last_modified = stored_last_modified

    # Fetch (no DB connection held during network I/O)
    try:
        iocs = await connector.run()
    except Exception as exc:
        logger.error("run_feed_sync_fetch_error", feed=feed_slug, error=redact_secrets(exc))
        async with AsyncSessionLocal() as session:
            result = await session.execute(select(FeedSource).where(FeedSource.id == feed_id))
            feed = result.scalar_one_or_none()
            if feed:
                # `last_sync_at` is deliberately NOT touched here. It means "last
                # SUCCESSFUL ingest" as of revision a7b8c9d00004, and advancing it on a
                # failure is what previously let a permanently broken feed look healthy
                # on dashboard/feed-health. The attempt is already recorded —
                # last_attempt_at was stamped before the fetch.
                feed.last_sync_status = "failed"
                feed.consecutive_failures = (feed.consecutive_failures or 0) + 1
                # Driver/HTTP errors can embed credentials — store a scrubbed
                # copy since this column is served to API clients.
                feed.last_sync_error = redact_secrets(exc)[:2000]
                await session.commit()
        return

    # ── 304 Not Modified: a SUCCESSFUL sync with nothing to ingest ───────────────
    #
    # Distinct from `no_data`. The source has asserted the file is unchanged, so there
    # is nothing to download, parse or write. Recording it as a failure would back a
    # healthy feed off to the 3-day cap, and the more reliably unchanged the source, the
    # worse the back-off.
    if getattr(connector, "not_modified", False):
        async with AsyncSessionLocal() as session:
            result = await session.execute(select(FeedSource).where(FeedSource.id == feed_id))
            feed = result.scalar_one_or_none()
            if feed:
                # `no_change`, NOT `success`: feed health must be able to distinguish
                # "checked, unchanged" from "fetched and ingested". A feed showing
                # no_change for three days is working correctly and must not render as
                # broken (Spec 2 §4.4).
                feed.last_sync_status = "no_change"
                feed.last_sync_at = attempt_started_at   # the check itself succeeded
                feed.last_sync_error = None
                feed.consecutive_failures = 0            # a no-change IS a success
                # ioc_count is deliberately NOT touched. Zeroing it would report the feed
                # as having contributed nothing, when it contributed exactly what it did
                # last time and the data is still there.
                #
                # The watermark is likewise untouched, and THE GAP CHECK IS SKIPPED
                # ENTIRELY rather than run against an absent file. `_check_window_continuity`
                # answers "did records fall through the gap between syncs"; a 304 is the
                # server asserting no records entered or aged out, so there is nothing to
                # have missed. Reporting a gap here would claim data loss that provably
                # did not happen. The stored watermark stays valid precisely because it
                # describes a file that still exists unchanged -- so a later 200 compares
                # against the right value however long the 304 streak ran.
                if getattr(connector, "next_http_etag", None):
                    feed.http_etag = connector.next_http_etag
                if getattr(connector, "next_http_last_modified", None):
                    feed.http_last_modified = connector.next_http_last_modified
                await session.commit()
        logger.info("run_feed_sync_not_modified", feed=feed_slug)
        return

    # Ingest — fresh session per attempt; ingest_iocs commits in chunks internally
    _MAX_RETRIES = 3
    # High-volume feeds (URLhaus ~34K, ThreatFox ~57K) need large batches to finish within timeout
    batch_size = 30 if feed_slug in ("urlhaus", "urlhaus-feed", "threatfox") else 30
    
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
                feed.consecutive_failures = 0  # a success ends any back-off streak

                # Persist the cursor ONLY after a successful ingest, and only if the
                # connector's fetch walked to completion (it leaves next_cursor None
                # otherwise). Two conditions, both required:
                #
                #   fetch completed  — else the un-fetched remainder would be skipped
                #                      permanently while the sync reported success
                #   ingest succeeded — else the rows are not stored, and advancing past
                #                      them would lose them just as thoroughly
                #
                # Writing it here, inside the same transaction that commits the ingest,
                # is what makes those two facts atomic.
                new_cursor = getattr(connector, "next_cursor", None)
                if new_cursor:
                    feed.sync_cursor = new_cursor

                # Store whatever validators the 200 carried, so the NEXT sync can ask
                # conditionally. Absent headers leave these unchanged rather than
                # clearing them: a server that omits ETag on one response has not
                # invalidated the one it gave us before.
                if getattr(connector, "next_http_etag", None):
                    feed.http_etag = connector.next_http_etag
                if getattr(connector, "next_http_last_modified", None):
                    feed.http_last_modified = connector.next_http_last_modified
                _check_window_continuity(feed, connector)
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


def _check_window_continuity(feed: FeedSource, connector) -> Optional[str]:
    """Detect records that fell between two syncs of a rolling-window export.

    A rolling-window source publishes "the last N hours". If the interval between
    syncs exceeds N, records that appeared and aged out in between are never seen —
    and nothing complains, because each individual sync looks perfectly healthy.
    That is the failure this makes visible.

    The test is contiguity: the new file's **earliest** record must be no later
    than the previous sync's **latest** record. If it is later, the interval
    between those two timestamps contains records nobody ingested.

    Mutates ``feed`` and returns a human-readable description of the gap, or None.
    Never raises: a monitoring aid must not be able to fail an ingest.
    """
    if not getattr(connector, "rolling_window", False):
        return None

    window = getattr(connector, "observed_window", None)
    if not window:
        return None

    try:
        new_min, new_max = window
        # Stored naive UTC, per the project-wide convention; the connector's
        # timestamps are tz-aware. Compare in one representation or TypeError.
        new_min_naive = new_min.replace(tzinfo=None) if new_min.tzinfo else new_min
        new_max_naive = new_max.replace(tzinfo=None) if new_max.tzinfo else new_max
        previous = feed.last_ingest_watermark

        gap_detail = None
        if previous is not None and new_min_naive > previous:
            missed = new_min_naive - previous
            gap_detail = (
                f"Rolling-window gap: previous sync saw records up to "
                f"{previous.isoformat()}, this file starts at "
                f"{new_min_naive.isoformat()} — {missed} of source history was "
                f"never ingested. The sync interval exceeds the export's window; "
                f"shorten it or accept the loss."
            )
            logger.error(
                "feed_rolling_window_gap",
                feed=feed.slug,
                previous_watermark=previous.isoformat(),
                new_window_start=new_min_naive.isoformat(),
                missed_duration=str(missed),
            )
        else:
            logger.info(
                "feed_rolling_window_contiguous",
                feed=feed.slug,
                window_start=new_min_naive.isoformat(),
                window_end=new_max_naive.isoformat(),
            )

        # Advance the watermark either way — never move it backwards, so a short
        # or partial file cannot lower it and manufacture a gap on the next run.
        if previous is None or new_max_naive > previous:
            feed.last_ingest_watermark = new_max_naive
        feed.last_ingest_gap = gap_detail
        return gap_detail
    except Exception as exc:  # pragma: no cover - defensive
        logger.warning(
            "feed_window_continuity_check_failed",
            feed=getattr(feed, "slug", "?"),
            error=redact_secrets(exc),
        )
        return None


async def _mark_failed(feed_id: str, error: str) -> None:
    """Persist a 'failed' status on the feed row in a fresh session."""
    async with AsyncSessionLocal() as session:
        result = await session.execute(select(FeedSource).where(FeedSource.id == feed_id))
        feed = result.scalar_one_or_none()
        if feed:
            # Same rule as the fetch-failure path: `last_sync_at` means "last SUCCESSFUL
            # ingest" (revision a7b8c9d00004) and must not advance on a failure, or a
            # permanently broken feed reads as recently synced. The attempt itself is
            # already recorded — last_attempt_at is stamped before the fetch.
            feed.last_sync_status = "failed"
            feed.consecutive_failures = (feed.consecutive_failures or 0) + 1
            feed.last_sync_error = redact_secrets(error)[:2000]
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
        # `last_attempt_at`, NOT `last_sync_at`. The attempt timestamp is stamped before
        # the fetch, so this yields exact intervals; last_sync_at is stamped at
        # completion and would make every interval sync_frequency + sync_duration.
        # last_sync_at is now purely a feed-health field. See design notes §1.3.1.
        #
        # Migration a7b8c9d00004 backfills last_attempt_at from last_sync_at, so
        # existing feeds are not all judged overdue on the first tick after deploy. A
        # genuinely new feed row still has NULL here and fires immediately, which is
        # correct.
        last = feed.last_attempt_at  # naive UTC from MySQL, or None
        # BACK-OFF (Section D4). A feed with consecutive failures waits longer between
        # attempts, so a dead feed stops consuming a sync slot in every window. The
        # counter resets to 0 on a successful ingest AND on a no-change sync, so a
        # working feed never accumulates back-off.
        interval = _effective_interval(freq, feed.consecutive_failures or 0)
        overdue = last is None or (now - last).total_seconds() >= interval

        if overdue:
            connector_path = FEED_CONNECTORS.get(feed.slug)
            if not connector_path:
                logger.warning("scheduler_no_connector", slug=feed.slug)
                continue

            logger.info(
                "scheduler_triggering_sync",
                feed=feed.slug,
                freq=freq,
                effective_interval=interval,
                consecutive_failures=feed.consecutive_failures or 0,
            )
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
