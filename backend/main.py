"""
FastAPI Endpoint for Celery-based Feed Processing.

This file integrates Celery tasks with the existing FastAPI application.
Add these endpoints to your app/api/feeds.py or create a new router.

Usage:
    1. Copy the sync_feed_celery() endpoint to app/api/feeds.py
    2. Or import this router and include it in app/main.py
    3. Call POST /api/v1/feeds/sync-celery/{feed_slug} to trigger async processing
"""

from typing import Optional, Dict, Any
from fastapi import APIRouter, HTTPException, BackgroundTasks, Query
from pydantic import BaseModel
import structlog

# Import Celery tasks
from tasks import sync_feed_task, celery_ping
from celery.result import AsyncResult

logger = structlog.get_logger()

# Create router
router = APIRouter(prefix="/api/v1/feeds", tags=["feeds-celery"])


# ============================================================================
# RESPONSE MODELS
# ============================================================================

class TaskSubmittedResponse(BaseModel):
    """Response when task is successfully queued."""
    message: str
    task_id: str
    feed_slug: str
    status_url: str
    
    class Config:
        json_schema_extra = {
            "example": {
                "message": "Feed sync task submitted successfully",
                "task_id": "a1b2c3d4-e5f6-4a5b-8c9d-0e1f2a3b4c5d",
                "feed_slug": "urlhaus",
                "status_url": "/api/v1/feeds/task-status/a1b2c3d4-e5f6-4a5b-8c9d-0e1f2a3b4c5d",
            }
        }


class TaskStatusResponse(BaseModel):
    """Task status check response."""
    task_id: str
    status: str  # PENDING, STARTED, SUCCESS, FAILURE, RETRY
    result: Optional[Dict[str, Any]] = None
    error: Optional[str] = None
    
    class Config:
        json_schema_extra = {
            "example": {
                "task_id": "a1b2c3d4-e5f6-4a5b-8c9d-0e1f2a3b4c5d",
                "status": "SUCCESS",
                "result": {
                    "feed_slug": "urlhaus",
                    "total_records": 56000,
                    "total_inserted": 55800,
                    "total_failed": 200,
                    "duration_seconds": 145.3,
                },
            }
        }


# ============================================================================
# ENDPOINTS
# ============================================================================

@router.post("/sync-celery/{feed_slug}", response_model=TaskSubmittedResponse)
async def sync_feed_celery(
    feed_slug: str,
    force: bool = Query(False, description="Force sync even if recently synced"),
    chunk_size: int = Query(1000, ge=100, le=10000, description="Records per chunk"),
):
    """
    Trigger asynchronous feed synchronization using Celery.
    
    **This endpoint returns immediately** after queuing the task. The actual
    processing happens in background Celery workers.
    
    **How it works:**
    1. API receives request and validates input
    2. Task is queued to Redis (takes ~10ms)
    3. API returns task ID immediately
    4. Celery worker picks up task from queue
    5. Worker fetches feed data and splits into chunks
    6. Each chunk is processed in parallel by multiple workers
    7. Results are aggregated and stored in Redis
    
    **Advantages over synchronous processing:**
    - No timeout issues (Vercel 300s limit avoided)
    - Parallel processing (faster for large feeds)
    - Horizontal scaling (add more workers)
    - Automatic retries on failure
    - Task monitoring and status tracking
    
    **Example:**
    ```bash
    # Trigger sync
    curl -X POST "http://localhost:8000/api/v1/feeds/sync-celery/urlhaus?force=true"
    
    # Response:
    {
        "message": "Feed sync task submitted successfully",
        "task_id": "a1b2c3d4...",
        "feed_slug": "urlhaus",
        "status_url": "/api/v1/feeds/task-status/a1b2c3d4..."
    }
    
    # Check status
    curl "http://localhost:8000/api/v1/feeds/task-status/a1b2c3d4..."
    ```
    
    **Parameters:**
    - **feed_slug**: Feed identifier (urlhaus, threatfox, malwarebazaar, etc.)
    - **force**: Skip freshness check and force sync even if recently synced
    - **chunk_size**: Number of records per chunk (default: 1000)
    
    **Returns:**
    - **task_id**: Unique task identifier for status tracking
    - **status_url**: Endpoint to check task progress
    """
    logger.info(
        "feed_sync_request_received",
        feed_slug=feed_slug,
        force=force,
        chunk_size=chunk_size,
    )
    
    try:
        # ====================================================================
        # Queue task to Celery (non-blocking)
        # ====================================================================
        
        # submit task to Redis queue
        task = sync_feed_task.apply_async(
            kwargs={
                "feed_slug": feed_slug,
                "force": force,
                "chunk_size": chunk_size,
            },
            # Optional: Set priority (requires queue configuration)
            # priority=9,  # 0-9, higher = higher priority
            
            # Optional: Set queue routing
            # queue="high_priority",
        )
        
        logger.info(
            "feed_sync_task_queued",
            feed_slug=feed_slug,
            task_id=task.id,
        )
        
        # ====================================================================
        # Return task ID immediately
        # ====================================================================
        
        return TaskSubmittedResponse(
            message=f"Feed sync task submitted successfully for {feed_slug}",
            task_id=task.id,
            feed_slug=feed_slug,
            status_url=f"/api/v1/feeds/task-status/{task.id}",
        )
    
    except Exception as exc:
        logger.error(
            "feed_sync_task_submission_error",
            feed_slug=feed_slug,
            error=str(exc),
        )
        raise HTTPException(
            status_code=500,
            detail=f"Failed to queue feed sync task: {str(exc)}",
        )


@router.get("/task-status/{task_id}", response_model=TaskStatusResponse)
async def get_task_status(task_id: str):
    """
    Check the status of a Celery task.
    
    **Task States:**
    - **PENDING**: Task is waiting in queue
    - **STARTED**: Task is currently executing
    - **SUCCESS**: Task completed successfully
    - **FAILURE**: Task failed after all retries
    - **RETRY**: Task failed and will retry
    
    **Example:**
    ```bash
    curl "http://localhost:8000/api/v1/feeds/task-status/a1b2c3d4..."
    ```
    
    **Success Response:**
    ```json
    {
        "task_id": "a1b2c3d4...",
        "status": "SUCCESS",
        "result": {
            "feed_slug": "urlhaus",
            "total_records": 56000,
            "duration_seconds": 145.3
        }
    }
    ```
    
    **Failure Response:**
    ```json
    {
        "task_id": "a1b2c3d4...",
        "status": "FAILURE",
        "error": "Feed API returned 500 error"
    }
    ```
    """
    try:
        # Get task result from Redis
        task_result = AsyncResult(task_id, app=sync_feed_task.app)
        
        response = TaskStatusResponse(
            task_id=task_id,
            status=task_result.status,
        )
        
        # Add result if task completed
        if task_result.ready():
            if task_result.successful():
                response.result = task_result.result
            elif task_result.failed():
                response.error = str(task_result.info)
        
        return response
    
    except Exception as exc:
        logger.error(
            "task_status_check_error",
            task_id=task_id,
            error=str(exc),
        )
        raise HTTPException(
            status_code=500,
            detail=f"Failed to check task status: {str(exc)}",
        )


@router.get("/health/celery")
async def celery_health_check():
    """
    Check if Celery workers are running and responsive.
    
    This endpoint pings Celery workers to verify they can process tasks.
    
    **Returns:**
    - **status**: "healthy" if workers respond, "unhealthy" if not
    - **workers_online**: Number of active workers
    - **response_time_ms**: Time taken to get response
    """
    import time
    
    start = time.time()
    
    try:
        # Send ping task to workers
        task = celery_ping.apply_async(expires=5)
        result = task.get(timeout=5)
        
        duration_ms = round((time.time() - start) * 1000, 2)
        
        if result == "pong":
            return {
                "status": "healthy",
                "message": "Celery workers are online",
                "response_time_ms": duration_ms,
            }
        else:
            return {
                "status": "unhealthy",
                "message": "Unexpected response from workers",
                "response": result,
            }
    
    except Exception as exc:
        duration_ms = round((time.time() - start) * 1000, 2)
        
        return {
            "status": "unhealthy",
            "message": "No Celery workers available",
            "error": str(exc),
            "response_time_ms": duration_ms,
        }


# ============================================================================
# INTEGRATION WITH EXISTING APP
# ============================================================================

# Option 1: Include this router in app/main.py
# from main import router as celery_router
# app.include_router(celery_router)

# Option 2: Copy endpoints to app/api/feeds.py
# Just copy the sync_feed_celery() and get_task_status() functions
