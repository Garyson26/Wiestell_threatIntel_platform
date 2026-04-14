"""Feed ingestion service for fetching, parsing, and storing IOCs from feeds."""

import asyncio
import time
import uuid
from datetime import datetime, timezone
from typing import List, Dict, Any, Optional, Tuple

from sqlalchemy import select, tuple_, update as sa_update
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import Session

from app.models.ioc import IOC
from app.models.feed import FeedSource
from app.models.ioc_source import IOCSource
from app.services.scoring_engine import calculate_threat_score
from app.utils.db_retry import is_retryable_lock_error
from app.utils.ioc_validator import validate_ioc, normalize_ioc

import structlog

logger = structlog.get_logger()

# Default chunk size for bulk IOC processing. Smaller batches mean fewer rows
# touched per transaction, which reduces InnoDB lock contention. High-volume
# feeds like ThreatFox (~57k IOCs) can override this with a larger batch_size.
_DEFAULT_BATCH_SIZE = 100

# High-volume feeds require larger batches to complete within timeout limits
_HIGH_VOLUME_BATCH_SIZE = 500


def _now() -> datetime:
    """Return current UTC time as timezone-naive datetime (MySQL DateTime columns require this)."""
    return datetime.now(timezone.utc).replace(tzinfo=None)


def _strip_tz(dt: Optional[datetime]) -> Optional[datetime]:
    """Strip timezone info so MySQL accepts the value."""
    if dt is None:
        return None
    if hasattr(dt, "tzinfo") and dt.tzinfo is not None:
        return dt.replace(tzinfo=None)
    return dt


def _normalize_batch(raw_iocs: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """Validate, normalize, and deduplicate a list of raw IOC dicts."""
    out = []
    seen_keys: set = set()
    for raw in raw_iocs:
        ioc_type = raw.get("type", "")
        value = (raw.get("value") or "").strip()
        if not value or not ioc_type:
            continue
        if not validate_ioc(ioc_type, value):
            continue
        normalized = dict(raw)
        normalized["value"] = normalize_ioc(value, ioc_type)
        key = (ioc_type, normalized["value"])
        if key in seen_keys:
            continue  # deduplicate within-feed duplicate values
        seen_keys.add(key)
        out.append(normalized)
    dropped = len(raw_iocs) - len(out)
    if dropped > 0:
        logger.warning("ioc_validation_dropped", dropped=dropped, total=len(raw_iocs))
    return out


async def ingest_iocs(
    session: AsyncSession,
    feed: FeedSource,
    raw_iocs: List[Dict[str, Any]],
    batch_size: Optional[int] = None,
) -> int:
    """Ingest a batch of IOCs from a feed using bulk operations.

    Processes IOCs in small chunks (batch_size rows) and commits after each
    chunk to release InnoDB row locks promptly. Each chunk is wrapped in retry
    logic: on ER_LOCK_WAIT_TIMEOUT (1205) or ER_LOCK_DEADLOCK (1213) the
    chunk transaction is rolled back and retried with exponential back-off
    (1 s → 2 s → 4 s) via _process_async_chunk_with_retry.
    Returns the total number of IOCs processed.
    
    Args:
        session: Database session
        feed: FeedSource model
        raw_iocs: List of raw IOC dictionaries
        batch_size: Number of IOCs per commit (defaults to 15, use 500 for high-volume feeds)
    """
    if batch_size is None:
        batch_size = _DEFAULT_BATCH_SIZE
    
    valid = _normalize_batch(raw_iocs)
    total_batches = (len(valid) + batch_size - 1) // batch_size  # ceiling division
    logger.info("feed_ingest_start", feed=feed.name, valid=len(valid), total=len(raw_iocs), batch_size=batch_size, total_batches=total_batches)

    feed_id = feed.id
    feed_name = feed.name
    count = 0
    batch_num = 0

    for chunk_start in range(0, len(valid), batch_size):
        batch_num += 1
        chunk = valid[chunk_start : chunk_start + batch_size]
        chunk_count = await _process_async_chunk_with_retry(session, feed_id, chunk)
        count += chunk_count
        
        # Log progress every 10 batches to track ingestion progress
        if batch_num % 10 == 0 or batch_num == total_batches:
            logger.info("feed_ingest_progress", feed=feed_name, batch=batch_num, total_batches=total_batches, processed=count)

    # Re-fetch feed after the last chunk commit for the final status update.
    result = await session.execute(
        select(FeedSource).where(FeedSource.id == feed_id)
    )
    feed = result.scalar_one_or_none()
    if feed:
        feed.last_sync_at = _now()
        if count == 0:
            feed.last_sync_status = "no_data"
            logger.warning("feed_ingestion_no_data", feed=feed_name, raw_total=len(raw_iocs))
        else:
            feed.last_sync_status = "success"
        feed.ioc_count = count
        await session.flush()

    logger.info("feed_ingestion_complete", feed=feed_name, iocs_ingested=count)
    return count


async def _ingest_chunk(
    session: AsyncSession,
    feed: FeedSource,
    chunk: List[Dict[str, Any]],
) -> int:
    """Process one chunk: bulk-lookup existing IOCs, update or insert, link sources.

    Existing-row mutations are accumulated as plain dicts and applied via a
    single ``session.execute(sa_update(IOC), ...)`` executemany call.
    This holds InnoDB row locks only for the duration of that one statement
    instead of spreading them across the Python-side computation loop, which
    is the primary cause of ER_LOCK_WAIT_TIMEOUT (1205) under concurrent
    workers. New INSERTs still use individual savepoints to handle the
    UNIQUE(type, value) race with other concurrent workers gracefully.
    """
    # Build (type, value) lookup key for all IOCs in this chunk.
    keys: List[Tuple[str, str]] = [(r["type"], r["value"]) for r in chunk]

    # Single SELECT — read phase is lock-free (no FOR UPDATE here).
    existing_rows = await session.execute(
        select(IOC).where(tuple_(IOC.type, IOC.value).in_(keys))
    )
    existing_map: Dict[Tuple[str, str], IOC] = {
        (ioc.type, ioc.value): ioc for ioc in existing_rows.scalars()
    }

    count = 0
    ioc_ids: List[str] = []
    # Collect new field values WITHOUT mutating tracked ORM objects.
    # Mutating attributes marks each object dirty and causes SQLAlchemy to
    # emit N individual UPDATEs at flush time, holding row locks across the
    # entire Python loop. Using a plain dict + executemany UPDATE instead
    # sends one round-trip and releases locks immediately.
    update_mappings: List[Dict[str, Any]] = []

    for raw in chunk:
        key = (raw["type"], raw["value"])
        existing = existing_map.get(key)

        try:
            if existing:
                new_sighting = existing.sighting_count + 1
                merged_tags = list(
                    set(existing.tags or []) | set(raw.get("tags") or [])
                )
                merged_tech = list(
                    set(existing.mitre_techniques or [])
                    | set(raw.get("mitre_techniques") or [])
                )
                new_score = calculate_threat_score(
                    {
                        "type": existing.type,
                        "value": existing.value,
                        "threat_score": existing.threat_score,
                        "tags": merged_tags,
                        "mitre_techniques": merged_tech,
                        "last_seen": _now(),
                        "sighting_count": new_sighting,
                        "metadata": existing.metadata_,
                    },
                    source_count=max(new_sighting, 1),
                )
                update_mappings.append({
                    "id": existing.id,
                    "sighting_count": new_sighting,
                    "last_seen": _now(),
                    "tags": merged_tags,
                    "mitre_techniques": merged_tech,
                    "threat_score": new_score,
                    "updated_at": _now(),
                })
                ioc_ids.append(existing.id)
            else:
                score = raw.get("threat_score") or calculate_threat_score(raw, source_count=1)
                new_id = str(uuid.uuid4())
                new_ioc = IOC(
                    id=new_id,
                    type=raw["type"],
                    value=raw["value"],
                    threat_score=score,
                    confidence=raw.get("confidence", 50),
                    first_seen=_strip_tz(raw.get("first_seen")) or _now(),
                    last_seen=_strip_tz(raw.get("last_seen")) or _now(),
                    sighting_count=1,
                    tags=raw.get("tags", []),
                    metadata_=raw.get("metadata", {}),
                    mitre_techniques=raw.get("mitre_techniques", []),
                )
                try:
                    async with session.begin_nested():
                        session.add(new_ioc)
                        await session.flush()
                    existing_map[key] = new_ioc
                    ioc_ids.append(new_id)
                except IntegrityError:
                    # Another concurrent worker inserted this IOC between our
                    # SELECT and INSERT — fetch the winner's row and use it.
                    logger.warning(
                        "ioc_duplicate_skipped",
                        type=raw["type"],
                        value=raw.get("value", ""),
                    )
                    res = await session.execute(
                        select(IOC).where(
                            IOC.type == raw["type"], IOC.value == raw["value"]
                        )
                    )
                    refetched = res.scalar_one_or_none()
                    if refetched:
                        existing_map[key] = refetched
                        ioc_ids.append(refetched.id)

            count += 1
        except Exception as e:
            logger.error("ioc_chunk_error", error=str(e), value=raw.get("value", "")[:50])

    # Single executemany UPDATE — one DB round-trip, minimal lock window.
    # synchronize_session="evaluate" (default) updates the in-memory identity
    # map so the objects reflect their new values; this is a no-op if no
    # objects were loaded into the current session for these rows.
    if update_mappings:
        await session.execute(sa_update(IOC), update_mappings)

    # Flush pending new IOC inserts (already inside savepoints above, but
    # flush here to ensure everything is visible before IOCSource linking).
    await session.flush()

    # Bulk-check which (ioc_id, feed_id) source links already exist.
    if ioc_ids:
        existing_sources = await session.execute(
            select(IOCSource.ioc_id).where(
                IOCSource.feed_id == feed.id,
                IOCSource.ioc_id.in_(ioc_ids),
            )
        )
        already_linked = {row[0] for row in existing_sources}

        # Deduplicate ioc_ids within this chunk — the same URL can appear
        # multiple times in a feed (e.g. URLhaus), which would produce two
        # IOCSource rows for the same (ioc_id, feed_id) unique constraint.
        seen: set = set()
        new_sources = []
        for ioc_id in ioc_ids:
            if ioc_id not in already_linked and ioc_id not in seen:
                new_sources.append(IOCSource(ioc_id=ioc_id, feed_id=feed.id))
                seen.add(ioc_id)

        if new_sources:
            session.add_all(new_sources)

        await session.flush()

    return count


async def _process_async_chunk_with_retry(
    session: AsyncSession,
    feed_id: str,
    chunk: List[Dict[str, Any]],
    max_retries: int = 3,
    base_delay: float = 1.0,
) -> int:
    """Process one async chunk and commit; retry on InnoDB lock contention.

    On ER_LOCK_WAIT_TIMEOUT (1205) or ER_LOCK_DEADLOCK (1213) the entire
    chunk transaction is rolled back and re-executed after exponential
    back-off: 1 s, 2 s, 4 s. Rolling back before the next attempt resets
    the session to a clean state with no stale row locks.

    The feed row is re-fetched at the start of every attempt because
    ``rollback()`` expires all session-bound ORM objects — accessing an
    expired object's attributes raises DetachedInstanceError.
    """
    last_exc: Optional[Exception] = None
    for attempt in range(max_retries + 1):
        try:
            # Always re-fetch the feed; after a rollback the previously
            # loaded instance is expired and unusable.
            result = await session.execute(
                select(FeedSource).where(FeedSource.id == feed_id)
            )
            feed = result.scalar_one_or_none()
            if not feed:
                return 0

            count = await _ingest_chunk(session, feed, chunk)
            # Commit immediately — this releases all InnoDB row locks and is
            # the primary defence against ER_LOCK_WAIT_TIMEOUT (1205) when
            # multiple workers update overlapping IOC sets concurrently.
            await session.commit()
            return count
        except Exception as exc:
            # Always roll back on any error so the next attempt (or the
            # caller) starts from a clean transaction state.
            await session.rollback()
            if not is_retryable_lock_error(exc) or attempt == max_retries:
                raise
            last_exc = exc
            delay = base_delay * (2 ** attempt)
            logger.warning(
                "async_chunk_lock_retry",
                attempt=attempt + 1,
                max_retries=max_retries,
                delay_s=delay,
                error=str(exc),
            )
            await asyncio.sleep(delay)
    raise last_exc  # type: ignore[misc]  — unreachable, satisfies type-checkers


def _ingest_chunk_sync(
    session: Session,
    feed: FeedSource,
    chunk: List[Dict[str, Any]],
) -> int:
    """Process one chunk synchronously using bulk_update_mappings for minimal lock duration.

    Existing-row mutations are accumulated as plain dicts and applied via
    ``session.bulk_update_mappings(IOC, ...)``, which emits a single
    executemany UPDATE statement. This is far more efficient than per-row ORM
    flushes and holds InnoDB row locks only for the duration of that one
    statement instead of across the entire Python computation loop.
    """
    keys: List[Tuple[str, str]] = []
    normalized: List[Dict[str, Any]] = []
    for raw in chunk:
        ioc_type = raw.get("type", "")
        value = (raw.get("value") or "").strip()
        if not value or not ioc_type:
            continue
        if not validate_ioc(ioc_type, value):
            continue
        value = normalize_ioc(value, ioc_type)
        norm = dict(raw)
        norm["value"] = value
        norm["type"] = ioc_type
        normalized.append(norm)
        keys.append((ioc_type, value))

    if not normalized:
        return 0

    # Single SELECT to fetch all existing IOCs — read phase is lock-free.
    existing_map: Dict[Tuple[str, str], IOC] = {}
    if keys:
        existing_rows = session.query(IOC).filter(
            tuple_(IOC.type, IOC.value).in_(keys)
        ).all()
        existing_map = {(ioc.type, ioc.value): ioc for ioc in existing_rows}

    count = 0
    ioc_ids: List[str] = []
    # Collect new field values WITHOUT mutating tracked ORM objects.
    # Per-row attribute mutations mark each object dirty and cause SQLAlchemy
    # to emit N individual UPDATEs at flush time. bulk_update_mappings emits
    # a single executemany UPDATE instead, minimising lock contention.
    update_mappings: List[Dict[str, Any]] = []

    for raw in normalized:
        key = (raw["type"], raw["value"])
        existing = existing_map.get(key)
        try:
            if existing:
                new_sighting = existing.sighting_count + 1
                merged_tags = list(
                    set(existing.tags or []) | set(raw.get("tags") or [])
                )
                merged_tech = list(
                    set(existing.mitre_techniques or [])
                    | set(raw.get("mitre_techniques") or [])
                )
                new_score = calculate_threat_score(
                    {
                        "type": existing.type,
                        "value": existing.value,
                        "threat_score": existing.threat_score,
                        "tags": merged_tags,
                        "mitre_techniques": merged_tech,
                        "last_seen": _now(),
                        "sighting_count": new_sighting,
                        "metadata": existing.metadata_,
                    },
                    source_count=max(new_sighting, 1),
                )
                update_mappings.append({
                    "id": existing.id,
                    "sighting_count": new_sighting,
                    "last_seen": _now(),
                    "tags": merged_tags,
                    "mitre_techniques": merged_tech,
                    "threat_score": new_score,
                    "updated_at": _now(),
                })
                ioc_ids.append(existing.id)
            else:
                score = raw.get("threat_score") or calculate_threat_score(raw, source_count=1)
                new_ioc = IOC(
                    type=raw["type"],
                    value=raw["value"],
                    threat_score=score,
                    confidence=raw.get("confidence", 50),
                    first_seen=_strip_tz(raw.get("first_seen")) or _now(),
                    last_seen=_strip_tz(raw.get("last_seen")) or _now(),
                    sighting_count=1,
                    tags=raw.get("tags", []),
                    metadata_=raw.get("metadata", {}),
                    mitre_techniques=raw.get("mitre_techniques", []),
                )
                sp = session.begin_nested()
                try:
                    session.add(new_ioc)
                    session.flush()  # get the DB-assigned id
                    sp.commit()
                    existing_map[key] = new_ioc
                    ioc_ids.append(new_ioc.id)
                except IntegrityError:
                    sp.rollback()
                    # Another concurrent worker beat us to this INSERT.
                    logger.warning(
                        "ioc_duplicate_skipped",
                        type=raw["type"],
                        value=raw.get("value", ""),
                    )
                    refetched = session.query(IOC).filter(
                        IOC.type == raw["type"], IOC.value == raw["value"]
                    ).first()
                    if refetched:
                        existing_map[key] = refetched
                        ioc_ids.append(refetched.id)
            count += 1
        except Exception as e:
            logger.error("sync_chunk_ioc_error", error=str(e), value=raw.get("value", "")[:50])

    # Single executemany UPDATE for all existing-IOC mutations — far fewer
    # DB round-trips than per-row ORM flushes, and row locks are held only
    # during this one statement rather than across the entire Python loop.
    if update_mappings:
        session.bulk_update_mappings(IOC, update_mappings)

    # Flush any remaining pending objects (new IOCSource inserts added below).
    session.flush()

    # Link IOCSources — skip already-linked pairs.
    if ioc_ids:
        already_linked = {
            row[0]
            for row in session.query(IOCSource.ioc_id).filter(
                IOCSource.feed_id == feed.id,
                IOCSource.ioc_id.in_(ioc_ids),
            ).all()
        }
        seen: set = set()
        for ioc_id in ioc_ids:
            if ioc_id not in already_linked and ioc_id not in seen:
                session.add(IOCSource(ioc_id=ioc_id, feed_id=feed.id))
                seen.add(ioc_id)
        session.flush()

    return count


def _process_chunk_with_retry(
    session: Session,
    feed_id: str,
    chunk: List[Dict[str, Any]],
    max_retries: int = 3,
    base_delay: float = 1.0,
) -> int:
    """Process one sync chunk and commit; retry on InnoDB lock contention.

    On ER_LOCK_WAIT_TIMEOUT (1205) or ER_LOCK_DEADLOCK (1213) the transaction
    is rolled back and the chunk is re-processed after exponential back-off:
    1 s, 2 s, 4 s. Rolling back before the next attempt resets the session
    to a clean state with no outstanding row locks.

    The feed row is re-fetched at the start of every attempt because
    ``session.rollback()`` expires all session-bound ORM objects.
    """
    last_exc: Optional[Exception] = None
    for attempt in range(max_retries + 1):
        try:
            # Always re-fetch the feed; after a rollback the previously
            # loaded instance is expired and unusable.
            feed = session.query(FeedSource).filter(
                FeedSource.id == feed_id
            ).first()
            if not feed:
                return 0
            count = _ingest_chunk_sync(session, feed, chunk)
            # Commit immediately — releases InnoDB row locks and is the
            # primary defence against ER_LOCK_WAIT_TIMEOUT under concurrent
            # Celery workers.
            session.commit()
            return count
        except Exception as exc:
            # Always roll back so the next attempt starts cleanly.
            session.rollback()
            if not is_retryable_lock_error(exc) or attempt == max_retries:
                raise
            last_exc = exc
            delay = base_delay * (2 ** attempt)
            logger.warning(
                "chunk_lock_retry",
                attempt=attempt + 1,
                max_retries=max_retries,
                delay_s=delay,
                error=str(exc),
            )
            time.sleep(delay)
    raise last_exc  # type: ignore[misc]  — unreachable, satisfies type-checkers


def ingest_iocs_sync(
    session: Session,
    feed: FeedSource,
    raw_iocs: List[Dict[str, Any]],
    batch_size: Optional[int] = None,
) -> int:
    """Synchronous version for Celery tasks.

    Processes IOCs in chunks (batch_size rows) and commits after each chunk
    to release InnoDB row locks promptly. Each chunk is wrapped in retry
    logic: on ER_LOCK_WAIT_TIMEOUT (1205) or ER_LOCK_DEADLOCK (1213) the
    chunk transaction is rolled back and retried with exponential back-off
    (1 s → 2 s → 4 s) via _process_chunk_with_retry.
    
    Args:
        session: Database session
        feed: FeedSource model
        raw_iocs: List of raw IOC dictionaries
        batch_size: Number of IOCs per commit (defaults to 15, use 500 for high-volume feeds)
    """
    if batch_size is None:
        batch_size = _DEFAULT_BATCH_SIZE
    
    valid = _normalize_batch(raw_iocs)
    total_batches = (len(valid) + batch_size - 1) // batch_size  # ceiling division
    logger.info("sync_feed_ingest_start", feed=feed.name, valid=len(valid), total=len(raw_iocs), batch_size=batch_size, total_batches=total_batches)

    feed_id = feed.id
    feed_name = feed.name
    count = 0
    batch_num = 0

    for chunk_start in range(0, len(valid), batch_size):
        batch_num += 1
        chunk = valid[chunk_start : chunk_start + batch_size]
        chunk_count = _process_chunk_with_retry(session, feed_id, chunk)
        count += chunk_count
        
        # Log progress every 10 batches to track ingestion progress
        if batch_num % 10 == 0 or batch_num == total_batches:
            logger.info("sync_feed_ingest_progress", feed=feed_name, batch=batch_num, total_batches=total_batches, processed=count)

    # Final status update — re-fetch after the last chunk commit.
    feed = session.query(FeedSource).filter(FeedSource.id == feed_id).first()
    if feed:
        feed.last_sync_at = _now()
        feed.last_sync_status = "success" if count > 0 else "no_data"
        feed.ioc_count = count
        session.flush()

    logger.info("sync_feed_ingest_complete", feed=feed_name, iocs_ingested=count)
    return count
