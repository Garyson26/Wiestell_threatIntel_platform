"""Celery tasks for background enrichment."""

import asyncio
from uuid import UUID

import structlog
from app.tasks.celery_app import celery_app
from app.database import SyncSessionLocal
from app.models.ioc import IOC

logger = structlog.get_logger()


@celery_app.task(bind=True, name="app.tasks.enrichment_tasks.enrich_ioc_task")
def enrich_ioc_task(self, ioc_id: str):
    """Enrich a single IOC in the background."""
    logger.info("enrich_ioc_start", ioc_id=ioc_id)

    session = SyncSessionLocal()
    try:
        ioc = session.query(IOC).filter(IOC.id == UUID(ioc_id)).first()
        if not ioc:
            logger.error("ioc_not_found", ioc_id=ioc_id)
            return {"status": "error", "message": "IOC not found"}

        # For now, log that enrichment would happen
        logger.info("enrich_ioc_complete", ioc_id=ioc_id, type=ioc.type, value=ioc.value)
        return {"status": "success", "ioc_id": ioc_id}

    except Exception as e:
        logger.error("enrich_ioc_error", ioc_id=ioc_id, error=str(e))
        return {"status": "error", "message": str(e)}
    finally:
        session.close()


@celery_app.task(name="app.tasks.enrichment_tasks.batch_enrich")
def batch_enrich(ioc_ids: list):
    """Enrich multiple IOCs in batch."""
    results = []
    for ioc_id in ioc_ids:
        result = enrich_ioc_task.delay(ioc_id)
        results.append({"ioc_id": ioc_id, "task_id": str(result.id)})
    return results
