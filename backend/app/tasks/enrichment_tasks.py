"""Celery tasks for background enrichment."""

import asyncio
from typing import List, Optional
from datetime import datetime, timezone, timedelta

import structlog
from sqlalchemy import select, or_
from sqlalchemy.orm import selectinload

from app.tasks.celery_app import celery_app
from app.database import SyncSessionLocal, AsyncSessionLocal
from app.models.ioc import IOC
from app.models.enrichment import Enrichment
from app.services.enrichment_engine import enrich_ioc

logger = structlog.get_logger()


def _utcnow() -> datetime:
    """Return current UTC time as a timezone-naive datetime for MySQL DateTime columns."""
    return datetime.now(timezone.utc).replace(tzinfo=None)


async def _enrich_ioc_async(ioc_id: str) -> dict:
    """Async enrichment function called from sync Celery task."""
    async with AsyncSessionLocal() as session:
        try:
            result = await session.execute(
                select(IOC).options(selectinload(IOC.enrichments)).where(IOC.id == ioc_id)
            )
            ioc = result.scalar_one_or_none()
            
            if not ioc:
                logger.error("ioc_not_found", ioc_id=ioc_id)
                return {"status": "error", "message": "IOC not found"}

            # Run enrichment
            enrichments = await enrich_ioc(session, ioc)
            await session.commit()
            
            logger.info(
                "enrich_ioc_complete", 
                ioc_id=ioc_id, 
                type=ioc.type, 
                value=ioc.value,
                enrichment_count=len(enrichments)
            )
            return {
                "status": "success", 
                "ioc_id": ioc_id,
                "enrichments": len(enrichments)
            }
            
        except Exception as e:
            logger.error("enrich_ioc_error", ioc_id=ioc_id, error=str(e))
            await session.rollback()
            return {"status": "error", "message": str(e)}


@celery_app.task(bind=True, name="app.tasks.enrichment_tasks.enrich_ioc_task")
def enrich_ioc_task(self, ioc_id: str):
    """Enrich a single IOC in the background.
    
    This task runs the async enrichment engine to gather data from multiple
    sources (GeoIP, WHOIS, DNS, reputation) and persists it to the database.
    """
    logger.info("enrich_ioc_start", ioc_id=ioc_id)
    
    try:
        # Run async enrichment in an event loop
        loop = asyncio.get_event_loop()
        if loop.is_closed():
            loop = asyncio.new_event_loop()
            asyncio.set_event_loop(loop)
        
        result = loop.run_until_complete(_enrich_ioc_async(ioc_id))
        return result
        
    except Exception as e:
        logger.error("enrich_ioc_task_error", ioc_id=ioc_id, error=str(e))
        return {"status": "error", "message": str(e)}


@celery_app.task(name="app.tasks.enrichment_tasks.batch_enrich")
def batch_enrich(ioc_ids: list):
    """Enrich multiple IOCs in batch.
    
    Dispatches individual enrichment tasks for each IOC.
    """
    results = []
    for ioc_id in ioc_ids:
        result = enrich_ioc_task.delay(ioc_id)
        results.append({"ioc_id": ioc_id, "task_id": str(result.id)})
    return results


async def _find_unenriched_iocs_async(limit: int = 100) -> List[str]:
    """Find IOCs that have never been enriched or have expired enrichments."""
    async with AsyncSessionLocal() as session:
        # Find IOCs with no enrichments at all
        no_enrichment_query = (
            select(IOC.id)
            .outerjoin(Enrichment, IOC.id == Enrichment.ioc_id)
            .where(Enrichment.id.is_(None))
            .limit(limit // 2)
        )
        result = await session.execute(no_enrichment_query)
        ioc_ids = [row[0] for row in result.fetchall()]
        
        # Find IOCs with all enrichments expired
        if len(ioc_ids) < limit:
            remaining = limit - len(ioc_ids)
            expired_query = (
                select(IOC.id)
                .join(Enrichment, IOC.id == Enrichment.ioc_id)
                .where(
                    or_(
                        Enrichment.expires_at < _utcnow(),
                        Enrichment.expires_at.is_(None)
                    )
                )
                .group_by(IOC.id)
                .limit(remaining)
            )
            result = await session.execute(expired_query)
            ioc_ids.extend([row[0] for row in result.fetchall()])
        
        return ioc_ids


@celery_app.task(name="app.tasks.enrichment_tasks.enrich_unenriched_iocs")
def enrich_unenriched_iocs(limit: int = 100):
    """Periodic task to enrich IOCs that don't have enrichment data.
    
    This runs on a schedule to continuously enrich IOCs that were created
    from feeds but never enriched.
    """
    logger.info("enrich_unenriched_start", limit=limit)
    
    try:
        loop = asyncio.get_event_loop()
        if loop.is_closed():
            loop = asyncio.new_event_loop()
            asyncio.set_event_loop(loop)
        
        ioc_ids = loop.run_until_complete(_find_unenriched_iocs_async(limit))
        
        if not ioc_ids:
            logger.info("no_unenriched_iocs_found")
            return {"status": "success", "message": "No unenriched IOCs found", "count": 0}
        
        logger.info("dispatching_enrichment_tasks", count=len(ioc_ids))
        
        # Dispatch enrichment tasks
        for ioc_id in ioc_ids:
            enrich_ioc_task.delay(ioc_id)
        
        return {
            "status": "success",
            "message": f"Dispatched {len(ioc_ids)} enrichment tasks",
            "count": len(ioc_ids)
        }
        
    except Exception as e:
        logger.error("enrich_unenriched_error", error=str(e))
        return {"status": "error", "message": str(e)}
