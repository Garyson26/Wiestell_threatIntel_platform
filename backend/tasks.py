"""
Celery Tasks for SENTINEL Threat Intelligence Platform.

This module contains all background tasks for processing feed data, enrichment,
and other long-running operations. Tasks are executed asynchronously by Celery
workers, allowing the API to return immediate responses.

Key Tasks:
- process_feed_chunk: Process a batch of IOCs (1000 records)
- sync_feed_task: Orchestrate full feed synchronization
- enrich_ioc_task: Enrich single IOC with threat intelligence
"""

import traceback
from typing import List, Dict, Any, Optional
from datetime import datetime

from celery import Task, group, chord
from celery.exceptions import SoftTimeLimitExceeded
import structlog

from celery_app import celery_app
from db import bulk_insert_iocs, get_feed_source, update_feed_stats

# Initialize structured logger
logger = structlog.get_logger()


# ============================================================================
# CUSTOM BASE TASK (with error handling and logging)
# ============================================================================

class CallbackTask(Task):
    """
    Custom base task with enhanced error handling and logging.
    
    Features:
    - Automatic retry on failure (with exponential backoff)
    - Structured logging for all task events
    - Exception tracking and alerting
    - Task metrics collection
    """
    
    def on_success(self, retval, task_id, args, kwargs):
        """Called when task succeeds."""
        logger.info(
            "task_success",
            task_name=self.name,
            task_id=task_id,
            result=retval,
        )
    
    def on_retry(self, exc, task_id, args, kwargs, einfo):
        """Called when task is retried."""
        logger.warning(
            "task_retry",
            task_name=self.name,
            task_id=task_id,
            exception=str(exc),
            retry_count=self.request.retries,
        )
    
    def on_failure(self, exc, task_id, args, kwargs, einfo):
        """Called when task fails after all retries."""
        logger.error(
            "task_failure",
            task_name=self.name,
            task_id=task_id,
            exception=str(exc),
            traceback=str(einfo),
        )
        
        # TODO: Send alert email/Slack notification for critical failures
        # from app.utils.email_service import send_error_alert_email
        # send_error_alert_email(...)


# ============================================================================
# FEED PROCESSING TASKS
# ============================================================================

@celery_app.task(
    bind=True,
    base=CallbackTask,
    name="tasks.process_feed_chunk",
    max_retries=3,
    default_retry_delay=60,
    autoretry_for=(Exception,),
    retry_backoff=True,
    retry_backoff_max=600,
    retry_jitter=True,
)
def process_feed_chunk(
    self,
    feed_slug: str,
    chunk_index: int,
    chunk_data: List[Dict[str, Any]],
    total_chunks: int
) -> Dict[str, Any]:
    """
    Process a single chunk of feed data (1000 records).
    
    This task:
    1. Validates IOC data in the chunk
    2. Performs bulk insert into database
    3. Handles errors and retries automatically
    4. Returns processing statistics
    
    Args:
        feed_slug: Feed identifier (e.g., "urlhaus", "threatfox")
        chunk_index: Current chunk number (0-based)
        chunk_data: List of IOC dictionaries to process
        total_chunks: Total number of chunks (for progress tracking)
    
    Returns:
        Dict with processing statistics:
        {
            "feed_slug": str,
            "chunk_index": int,
            "records_processed": int,
            "records_inserted": int,
            "records_failed": int,
            "duration_seconds": float,
        }
    
    Raises:
        SoftTimeLimitExceeded: If task exceeds time limit
        Exception: Any other processing error (will trigger retry)
    """
    start_time = datetime.utcnow()
    task_id = self.request.id
    
    logger.info(
        "chunk_processing_start",
        task_id=task_id,
        feed_slug=feed_slug,
        chunk_index=chunk_index,
        chunk_size=len(chunk_data),
        total_chunks=total_chunks,
        progress_pct=round((chunk_index / total_chunks) * 100, 1),
    )
    
    try:
        # ====================================================================
        # STEP 1: Validate chunk data
        # ====================================================================
        
        if not chunk_data:
            logger.warning(
                "chunk_empty",
                feed_slug=feed_slug,
                chunk_index=chunk_index,
            )
            return {
                "feed_slug": feed_slug,
                "chunk_index": chunk_index,
                "records_processed": 0,
                "records_inserted": 0,
                "records_failed": 0,
                "duration_seconds": 0,
            }
        
        # ====================================================================
        # STEP 2: Bulk insert into database
        # ====================================================================
        
        # Call database layer (see db.py for implementation)
        insert_result = bulk_insert_iocs(
            feed_slug=feed_slug,
            iocs=chunk_data,
        )
        
        # ====================================================================
        # STEP 3: Calculate metrics
        # ====================================================================
        
        duration = (datetime.utcnow() - start_time).total_seconds()
        records_processed = len(chunk_data)
        records_inserted = insert_result["inserted"]
        records_failed = insert_result["failed"]
        
        logger.info(
            "chunk_processing_complete",
            task_id=task_id,
            feed_slug=feed_slug,
            chunk_index=chunk_index,
            records_processed=records_processed,
            records_inserted=records_inserted,
            records_failed=records_failed,
            duration_seconds=round(duration, 2),
            throughput_per_sec=round(records_processed / duration if duration > 0 else 0, 1),
        )
        
        return {
            "feed_slug": feed_slug,
            "chunk_index": chunk_index,
            "records_processed": records_processed,
            "records_inserted": records_inserted,
            "records_failed": records_failed,
            "duration_seconds": round(duration, 2),
        }
    
    except SoftTimeLimitExceeded:
        # Task exceeded soft time limit (55 minutes)
        logger.error(
            "chunk_processing_timeout",
            task_id=task_id,
            feed_slug=feed_slug,
            chunk_index=chunk_index,
        )
        raise  # Will trigger retry
    
    except Exception as exc:
        # Any other error - log and retry
        logger.error(
            "chunk_processing_error",
            task_id=task_id,
            feed_slug=feed_slug,
            chunk_index=chunk_index,
            error=str(exc),
            traceback=traceback.format_exc(),
        )
        
        # Retry with exponential backoff
        raise self.retry(exc=exc)


# ============================================================================
# FEED ORCHESTRATION TASK
# ============================================================================

@celery_app.task(
    bind=True,
    base=CallbackTask,
    name="tasks.sync_feed_task",
    max_retries=2,
    autoretry_for=(Exception,),
)
def sync_feed_task(
    self,
    feed_slug: str,
    force: bool = False,
    chunk_size: int = 1000,
) -> Dict[str, Any]:
    """
    Orchestrate full feed synchronization using parallel chunk processing.
    
    This is the main entry point for feed ingestion. It:
    1. Fetches raw data from feed source (API/CSV/etc)
    2. Splits data into chunks (default: 1000 records per chunk)
    3. Dispatches parallel Celery tasks for each chunk
    4. Waits for all chunks to complete
    5. Updates feed statistics
    
    Architecture:
        API Request
            |
            v
        sync_feed_task (this function)
            |
            +---> Fetch data from feed API
            |
            +---> Split into chunks [chunk1, chunk2, ..., chunkN]
            |
            +---> Dispatch parallel tasks
                  |
                  +---> process_feed_chunk(chunk1) --> Worker 1
                  +---> process_feed_chunk(chunk2) --> Worker 2
                  +---> process_feed_chunk(chunk3) --> Worker 3
                  |     ...
                  +---> process_feed_chunk(chunkN) --> Worker N
                  |
                  +---> Wait for all to complete
                  |
                  +---> Aggregate results
    
    Args:
        feed_slug: Feed identifier (e.g., "urlhaus")
        force: Force sync even if recently synced
        chunk_size: Records per chunk (default: 1000)
    
    Returns:
        Dict with sync statistics:
        {
            "feed_slug": str,
            "total_records": int,
            "total_chunks": int,
            "success": bool,
            "duration_seconds": float,
            "chunks_completed": int,
            "chunks_failed": int,
        }
    """
    start_time = datetime.utcnow()
    task_id = self.request.id
    
    logger.info(
        "feed_sync_start",
        task_id=task_id,
        feed_slug=feed_slug,
        force=force,
        chunk_size=chunk_size,
    )
    
    try:
        # ====================================================================
        # STEP 1: Fetch feed data from source
        # ====================================================================
        
        # Import feed connector dynamically
        # This allows adding new feeds without modifying this file
        try:
            from app.feeds import get_feed_connector
            
            feed_connector = get_feed_connector(feed_slug)
            if not feed_connector:
                raise ValueError(f"Unknown feed: {feed_slug}")
            
            logger.info(
                "feed_fetch_start",
                feed_slug=feed_slug,
                connector=feed_connector.__class__.__name__,
            )
            
            # Fetch raw data (this calls the feed API/downloads CSV)
            raw_data = feed_connector.fetch()
            
            if not raw_data or "iocs" not in raw_data:
                raise ValueError(f"No data returned from feed: {feed_slug}")
            
            iocs = raw_data["iocs"]
            total_records = len(iocs)
            
            logger.info(
                "feed_fetch_complete",
                feed_slug=feed_slug,
                total_records=total_records,
            )
        
        except Exception as exc:
            logger.error(
                "feed_fetch_error",
                feed_slug=feed_slug,
                error=str(exc),
            )
            raise
        
        # ====================================================================
        # STEP 2: Split data into chunks
        # ====================================================================
        
        chunks = [
            iocs[i:i + chunk_size]
            for i in range(0, len(iocs), chunk_size)
        ]
        total_chunks = len(chunks)
        
        logger.info(
            "feed_chunking_complete",
            feed_slug=feed_slug,
            total_records=total_records,
            total_chunks=total_chunks,
            chunk_size=chunk_size,
        )
        
        # ====================================================================
        # STEP 3: Dispatch parallel chunk processing tasks
        # ====================================================================
        
        # Create a group of tasks (all run in parallel)
        chunk_tasks = group(
            process_feed_chunk.s(
                feed_slug=feed_slug,
                chunk_index=idx,
                chunk_data=chunk,
                total_chunks=total_chunks,
            )
            for idx, chunk in enumerate(chunks)
        )
        
        # Execute all tasks in parallel and wait for results
        # Note: This will block until all chunks complete
        # For async dispatch, use: chunk_tasks.apply_async()
        logger.info(
            "feed_chunks_dispatching",
            feed_slug=feed_slug,
            total_chunks=total_chunks,
        )
        
        results = chunk_tasks.apply_async()
        chunk_results = results.get(timeout=7200)  # 2 hour timeout
        
        # ====================================================================
        # STEP 4: Aggregate results from all chunks
        # ====================================================================
        
        total_processed = sum(r["records_processed"] for r in chunk_results)
        total_inserted = sum(r["records_inserted"] for r in chunk_results)
        total_failed = sum(r["records_failed"] for r in chunk_results)
        chunks_completed = len([r for r in chunk_results if r["records_processed"] > 0])
        
        duration = (datetime.utcnow() - start_time).total_seconds()
        
        logger.info(
            "feed_sync_complete",
            task_id=task_id,
            feed_slug=feed_slug,
            total_records=total_processed,
            total_inserted=total_inserted,
            total_failed=total_failed,
            chunks_completed=chunks_completed,
            total_chunks=total_chunks,
            duration_seconds=round(duration, 2),
        )
        
        # ====================================================================
        # STEP 5: Update feed statistics in database
        # ====================================================================
        
        update_feed_stats(
            feed_slug=feed_slug,
            last_sync=datetime.utcnow(),
            total_iocs=total_inserted,
        )
        
        return {
            "feed_slug": feed_slug,
            "total_records": total_processed,
            "total_inserted": total_inserted,
            "total_failed": total_failed,
            "total_chunks": total_chunks,
            "chunks_completed": chunks_completed,
            "chunks_failed": total_chunks - chunks_completed,
            "success": True,
            "duration_seconds": round(duration, 2),
        }
    
    except Exception as exc:
        logger.error(
            "feed_sync_error",
            task_id=task_id,
            feed_slug=feed_slug,
            error=str(exc),
            traceback=traceback.format_exc(),
        )
        
        # Retry if transient error
        if self.request.retries < self.max_retries:
            raise self.retry(exc=exc, countdown=120)  # Retry after 2 minutes
        
        # Final failure after all retries
        return {
            "feed_slug": feed_slug,
            "success": False,
            "error": str(exc),
        }


# ============================================================================
# ENRICHMENT TASKS
# ============================================================================

@celery_app.task(
    bind=True,
    base=CallbackTask,
    name="tasks.enrich_ioc_task",
    max_retries=3,
)
def enrich_ioc_task(
    self,
    ioc_id: int,
    enrichment_types: Optional[List[str]] = None,
) -> Dict[str, Any]:
    """
    Enrich a single IOC with threat intelligence data.
    
    Enrichment sources:
    - GeoIP: Location data for IP addresses
    - WHOIS: Domain registration info
    - DNS: DNS records and history
    - Reputation: Threat scores from external APIs
    - Shodan: Device/service information
    
    Args:
        ioc_id: Database ID of IOC to enrich
        enrichment_types: List of enrichment types to run
                         (default: all available)
    
    Returns:
        Dict with enrichment results
    """
    logger.info(
        "ioc_enrichment_start",
        ioc_id=ioc_id,
        enrichment_types=enrichment_types or "all",
    )
    
    try:
        # Import enrichment engine
        from app.services.enrichment_engine import enrich_ioc
        
        # Run enrichment (this calls external APIs)
        result = enrich_ioc(ioc_id, enrichment_types)
        
        logger.info(
            "ioc_enrichment_complete",
            ioc_id=ioc_id,
            enrichments_added=len(result.get("enrichments", [])),
        )
        
        return result
    
    except Exception as exc:
        logger.error(
            "ioc_enrichment_error",
            ioc_id=ioc_id,
            error=str(exc),
        )
        raise self.retry(exc=exc)


# ============================================================================
# MAINTENANCE TASKS
# ============================================================================

@celery_app.task(name="tasks.cleanup_old_iocs")
def cleanup_old_iocs(days: int = 90) -> Dict[str, Any]:
    """
    Clean up IOCs older than specified days.
    
    This task runs periodically (e.g., weekly) to prevent database bloat.
    
    Args:
        days: Delete IOCs older than this many days
    
    Returns:
        Dict with cleanup statistics
    """
    logger.info("cleanup_start", days=days)
    
    # TODO: Implement cleanup logic
    # from app.database import AsyncSessionLocal
    # from app.models import IOC
    # ...
    
    return {"deleted": 0, "days": days}


if __name__ == "__main__":
    # Test task execution
    print("Testing Celery tasks...")
    
    # Test data
    test_chunk = [
        {"type": "url", "value": "http://malicious.com", "source": "test"},
        {"type": "ip", "value": "1.2.3.4", "source": "test"},
    ]
    
    # Synchronous test
    result = process_feed_chunk(
        feed_slug="test",
        chunk_index=0,
        chunk_data=test_chunk,
        total_chunks=1,
    )
    
    print(f"Test result: {result}")
