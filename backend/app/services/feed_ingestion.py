"""Feed ingestion service for fetching, parsing, and storing IOCs from feeds."""

import uuid
from datetime import datetime, timezone
from typing import List, Dict, Any, Optional, Tuple

from sqlalchemy import select, tuple_
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import Session

from app.models.ioc import IOC
from app.models.feed import FeedSource
from app.models.ioc_source import IOCSource
from app.services.scoring_engine import calculate_threat_score
from app.utils.ioc_validator import validate_ioc, normalize_ioc

import structlog

logger = structlog.get_logger()

# Process IOCs in chunks to avoid huge IN-clauses, memory spikes, and
# "Query too large" / "Lost connection" (error 2013) on MySQL.
# 50 rows keeps each UPDATE executemany well within MySQL's max_allowed_packet
# and releases InnoDB row locks promptly between chunks.
_BATCH_SIZE = 50


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
) -> int:
    """Ingest a batch of IOCs from a feed using bulk operations.

    Processes IOCs in chunks and commits after each chunk so that row-level
    locks are released promptly. This prevents MySQL lock wait timeout (1205)
    when a large feed (e.g. OTX) updates hundreds of existing IOC rows.
    Returns the total number of IOCs processed.
    """
    valid = _normalize_batch(raw_iocs)
    logger.info("feed_ingest_start", feed=feed.name, valid=len(valid), total=len(raw_iocs))

    feed_id = feed.id
    feed_name = feed.name
    count = 0
    for chunk_start in range(0, len(valid), _BATCH_SIZE):
        chunk = valid[chunk_start : chunk_start + _BATCH_SIZE]

        # After the first commit the session expires all objects; re-fetch feed
        # so _ingest_chunk receives a live instance with a valid .id.
        if chunk_start > 0:
            result = await session.execute(
                select(FeedSource).where(FeedSource.id == feed_id)
            )
            feed = result.scalar_one_or_none()
            if not feed:
                break

        count += await _ingest_chunk(session, feed, chunk)

        # Commit after every chunk to release InnoDB row locks immediately,
        # preventing lock wait timeouts on subsequent concurrent transactions.
        await session.commit()

    # Re-fetch feed after the last commit for the final status update.
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
    """Process one chunk: bulk-lookup existing IOCs, update or insert, link sources."""
    # Build (type, value) lookup key for all IOCs in this chunk
    keys: List[Tuple[str, str]] = [(r["type"], r["value"]) for r in chunk]

    # Single query to fetch all existing IOCs in this chunk
    existing_rows = await session.execute(
        select(IOC).where(tuple_(IOC.type, IOC.value).in_(keys))
    )
    existing_map: Dict[Tuple[str, str], IOC] = {
        (ioc.type, ioc.value): ioc for ioc in existing_rows.scalars()
    }

    count = 0
    ioc_ids: List[str] = []

    for raw in chunk:
        key = (raw["type"], raw["value"])
        existing = existing_map.get(key)

        try:
            if existing:
                existing.sighting_count += 1
                existing.last_seen = _now()
                if raw.get("tags"):
                    merged = set(existing.tags or [])
                    merged.update(raw["tags"])
                    existing.tags = list(merged)
                if raw.get("mitre_techniques"):
                    merged_tech = set(existing.mitre_techniques or [])
                    merged_tech.update(raw["mitre_techniques"])
                    existing.mitre_techniques = list(merged_tech)
                existing.threat_score = calculate_threat_score(
                    {
                        "type": existing.type,
                        "value": existing.value,
                        "threat_score": existing.threat_score,
                        "tags": existing.tags,
                        "mitre_techniques": existing.mitre_techniques,
                        "last_seen": existing.last_seen,
                        "sighting_count": existing.sighting_count,
                        "metadata": existing.metadata_,
                    },
                    source_count=max(existing.sighting_count, 1),
                )
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

    # Flush updates to existing IOCs before inserting IOCSources
    await session.flush()

    # Bulk-check which (ioc_id, feed_id) source links already exist
    if ioc_ids:
        existing_sources = await session.execute(
            select(IOCSource.ioc_id).where(
                IOCSource.feed_id == feed.id,
                IOCSource.ioc_id.in_(ioc_ids),
            )
        )
        already_linked = {row[0] for row in existing_sources}

        # Deduplicate ioc_ids within this chunk — same URL can appear multiple
        # times in a feed (e.g. URLhaus), which would cause two IOCSource inserts
        # for the same (ioc_id, feed_id) and violate the unique constraint.
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


def _ingest_chunk_sync(
    session: Session,
    feed: FeedSource,
    chunk: List[Dict[str, Any]],
) -> int:
    """Process one chunk synchronously: bulk-lookup, update or insert, link sources."""
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

    existing_map: Dict[Tuple[str, str], IOC] = {}
    if keys:
        existing_rows = session.query(IOC).filter(
            tuple_(IOC.type, IOC.value).in_(keys)
        ).all()
        existing_map = {(ioc.type, ioc.value): ioc for ioc in existing_rows}

    count = 0
    ioc_ids: List[str] = []

    for raw in normalized:
        key = (raw["type"], raw["value"])
        existing = existing_map.get(key)
        try:
            if existing:
                existing.sighting_count += 1
                existing.last_seen = _now()
                if raw.get("tags"):
                    merged = set(existing.tags or [])
                    merged.update(raw["tags"])
                    existing.tags = list(merged)
                if raw.get("mitre_techniques"):
                    merged_tech = set(existing.mitre_techniques or [])
                    merged_tech.update(raw["mitre_techniques"])
                    existing.mitre_techniques = list(merged_tech)
                existing.threat_score = calculate_threat_score(
                    {
                        "type": existing.type,
                        "value": existing.value,
                        "threat_score": existing.threat_score,
                        "tags": existing.tags,
                        "mitre_techniques": existing.mitre_techniques or [],
                        "last_seen": existing.last_seen,
                        "sighting_count": existing.sighting_count,
                        "metadata": existing.metadata_,
                    },
                    source_count=max(existing.sighting_count, 1),
                )
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

    # Bulk-flush pending UPDATE/INSERT rows before linking sources
    session.flush()

    # Link IOCSources — skip already-linked pairs
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


def ingest_iocs_sync(
    session: Session,
    feed: FeedSource,
    raw_iocs: List[Dict[str, Any]],
) -> int:
    """Synchronous version for Celery tasks.

    Processes IOCs in chunks of _BATCH_SIZE and commits after each chunk so
    that the UPDATE executemany stays well under MySQL's max_allowed_packet
    and InnoDB row locks are released promptly.
    """
    valid = _normalize_batch(raw_iocs)
    logger.info("sync_feed_ingest_start", feed=feed.name, valid=len(valid), total=len(raw_iocs))

    feed_id = feed.id
    feed_name = feed.name
    count = 0

    for chunk_start in range(0, len(valid), _BATCH_SIZE):
        chunk = valid[chunk_start : chunk_start + _BATCH_SIZE]

        # Re-fetch feed after commits so SQLAlchemy has a live instance
        if chunk_start > 0:
            feed = session.query(FeedSource).filter(FeedSource.id == feed_id).first()
            if not feed:
                break

        count += _ingest_chunk_sync(session, feed, chunk)

        # Commit after every chunk — releases InnoDB row locks and keeps
        # the UPDATE executemany size bounded to _BATCH_SIZE rows.
        session.commit()

    # Final status update
    feed = session.query(FeedSource).filter(FeedSource.id == feed_id).first()
    if feed:
        feed.last_sync_at = _now()
        feed.last_sync_status = "success" if count > 0 else "no_data"
        feed.ioc_count = count
        session.flush()

    logger.info("sync_feed_ingest_complete", feed=feed_name, iocs_ingested=count)
    return count
