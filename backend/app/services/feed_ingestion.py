"""Feed ingestion service for fetching, parsing, and storing IOCs from feeds."""

from datetime import datetime, timezone
from typing import List, Dict, Any, Optional

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import Session

from app.models.ioc import IOC
from app.models.feed import FeedSource
from app.models.ioc_source import IOCSource
from app.services.scoring_engine import calculate_threat_score
from app.utils.ioc_validator import validate_ioc, normalize_ioc

import structlog

logger = structlog.get_logger()


async def ingest_iocs(
    session: AsyncSession,
    feed: FeedSource,
    raw_iocs: List[Dict[str, Any]],
) -> int:
    """Ingest a batch of IOCs from a feed.
    
    Handles deduplication, normalization, scoring, and storage.
    Returns the number of new/updated IOCs.
    """
    count = 0

    for raw in raw_iocs:
        try:
            ioc_type = raw.get("type", "")
            value = raw.get("value", "").strip()

            if not value or not ioc_type:
                continue

            if not validate_ioc(ioc_type, value):
                logger.warning("invalid_ioc", type=ioc_type, value=value[:50])
                continue

            value = normalize_ioc(value, ioc_type)

            result = await session.execute(
                select(IOC).where(IOC.type == ioc_type, IOC.value == value)
            )
            existing = result.scalar_one_or_none()

            if existing:
                existing.sighting_count += 1
                existing.last_seen = datetime.now(timezone.utc)
                
                if raw.get("tags"):
                    existing_tags = set(existing.tags or [])
                    existing_tags.update(raw["tags"])
                    existing.tags = list(existing_tags)
                
                if raw.get("mitre_techniques"):
                    existing_tech = set(existing.mitre_techniques or [])
                    existing_tech.update(raw["mitre_techniques"])
                    existing.mitre_techniques = list(existing_tech)

                source_count = len(existing.sources) if existing.sources else 1
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
                    source_count=source_count + 1,
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
                    first_seen=raw.get("first_seen", datetime.now(timezone.utc)),
                    last_seen=raw.get("last_seen", datetime.now(timezone.utc)),
                    sighting_count=1,
                    tags=raw.get("tags", []),
                    metadata_=raw.get("metadata", {}),
                    mitre_techniques=raw.get("mitre_techniques", []),
                )
                session.add(new_ioc)
                await session.flush()
                ioc_id = new_ioc.id

            existing_source = await session.execute(
                select(IOCSource).where(
                    IOCSource.ioc_id == ioc_id,
                    IOCSource.feed_id == feed.id,
                )
            )
            if existing_source.scalar_one_or_none() is None:
                ioc_source = IOCSource(
                    ioc_id=ioc_id,
                    feed_id=feed.id,
                    raw_data=raw.get("raw_data"),
                )
                session.add(ioc_source)

            count += 1

        except Exception as e:
            logger.error("ioc_ingestion_error", error=str(e), value=raw.get("value", "")[:50])
            continue

    feed.last_sync_at = datetime.now(timezone.utc)
    feed.last_sync_status = "success"
    feed.ioc_count = count
    
    await session.flush()
    
    logger.info("feed_ingestion_complete", feed=feed.name, iocs_ingested=count)
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
                existing.last_seen = datetime.now(timezone.utc)
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
                    first_seen=raw.get("first_seen", datetime.now(timezone.utc)),
                    last_seen=raw.get("last_seen", datetime.now(timezone.utc)),
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

    feed.last_sync_at = datetime.now(timezone.utc)
    feed.last_sync_status = "success"
    feed.ioc_count = count
    session.flush()

    return count
