"""Feed ingestion service for fetching, parsing, and storing IOCs from feeds."""

import uuid
from datetime import datetime, timezone
from typing import List, Dict, Any, Optional, Tuple

from sqlalchemy import select, tuple_
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import Session

from app.models.ioc import IOC
from app.models.feed import FeedSource
from app.models.ioc_source import IOCSource
from app.services.scoring_engine import calculate_threat_score
from app.utils.ioc_validator import validate_ioc, normalize_ioc

import structlog

logger = structlog.get_logger()

# Process IOCs in chunks to avoid huge IN-clauses and memory spikes
_BATCH_SIZE = 500


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
    """Validate and normalize a list of raw IOC dicts. Returns only valid ones."""
    out = []
    for raw in raw_iocs:
        ioc_type = raw.get("type", "")
        value = (raw.get("value") or "").strip()
        if not value or not ioc_type:
            continue
        if not validate_ioc(ioc_type, value):
            continue
        normalized = dict(raw)
        normalized["value"] = normalize_ioc(value, ioc_type)
        out.append(normalized)
    return out


async def ingest_iocs(
    session: AsyncSession,
    feed: FeedSource,
    raw_iocs: List[Dict[str, Any]],
) -> int:
    """Ingest a batch of IOCs from a feed using bulk operations.

    Processes IOCs in chunks to avoid query timeouts on large feeds.
    Returns the total number of IOCs processed.
    """
    valid = _normalize_batch(raw_iocs)
    logger.info("feed_ingest_start", feed=feed.name, valid=len(valid), total=len(raw_iocs))

    count = 0
    for chunk_start in range(0, len(valid), _BATCH_SIZE):
        chunk = valid[chunk_start : chunk_start + _BATCH_SIZE]
        count += await _ingest_chunk(session, feed, chunk)

    feed.last_sync_at = _now()
    feed.last_sync_status = "success"
    feed.ioc_count = count

    await session.flush()
    logger.info("feed_ingestion_complete", feed=feed.name, iocs_ingested=count)
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
                session.add(new_ioc)
                # Add to map so duplicate values in same chunk don't double-insert
                existing_map[key] = new_ioc
                ioc_ids.append(new_id)

            count += 1
        except Exception as e:
            logger.error("ioc_chunk_error", error=str(e), value=raw.get("value", "")[:50])

    # Flush to get DB IDs for new IOCs before inserting IOCSources
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

        new_sources = [
            IOCSource(ioc_id=ioc_id, feed_id=feed.id)
            for ioc_id in ioc_ids
            if ioc_id not in already_linked
        ]
        if new_sources:
            session.add_all(new_sources)

        await session.flush()

    return count
    return count


def ingest_iocs_sync(
    session: Session,
    feed: FeedSource,
    raw_iocs: List[Dict[str, Any]],
) -> int:
    """Synchronous version for Celery tasks."""
    count = 0

    for raw in raw_iocs:
        try:
            ioc_type = raw.get("type", "")
            value = raw.get("value", "").strip()

            if not value or not ioc_type:
                continue
            if not validate_ioc(ioc_type, value):
                continue

            value = normalize_ioc(value, ioc_type)

            existing = session.query(IOC).filter(
                IOC.type == ioc_type, IOC.value == value
            ).first()

            if existing:
                existing.sighting_count += 1
                existing.last_seen = _now()
                if raw.get("tags"):
                    existing_tags = set(existing.tags or [])
                    existing_tags.update(raw["tags"])
                    existing.tags = list(existing_tags)
                
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
                    source_count=2,
                )
                ioc_id = existing.id
            else:
                score = raw.get("threat_score")
                if score is None:
                    score = calculate_threat_score(raw, source_count=1)

                new_ioc = IOC(
                    type=ioc_type,
                    value=value,
                    threat_score=score,
                    confidence=raw.get("confidence", 50),
                    first_seen=_strip_tz(raw.get("first_seen")) or _now(),
                    last_seen=_strip_tz(raw.get("last_seen")) or _now(),
                    sighting_count=1,
                    tags=raw.get("tags", []),
                    metadata_=raw.get("metadata", {}),
                    mitre_techniques=raw.get("mitre_techniques", []),
                )
                session.add(new_ioc)
                session.flush()
                ioc_id = new_ioc.id

            existing_source = session.query(IOCSource).filter(
                IOCSource.ioc_id == ioc_id,
                IOCSource.feed_id == feed.id,
            ).first()
            if existing_source is None:
                ioc_source = IOCSource(
                    ioc_id=ioc_id,
                    feed_id=feed.id,
                    raw_data=raw.get("raw_data"),
                )
                session.add(ioc_source)

            count += 1
        except Exception as e:
            logger.error("sync_ingestion_error", error=str(e))
            continue

    feed.last_sync_at = _now()
    feed.last_sync_status = "success"
    feed.ioc_count = count
    session.flush()

    return count
