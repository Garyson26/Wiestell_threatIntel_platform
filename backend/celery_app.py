"""
Celery Application Configuration for SENTINEL Threat Intelligence Platform.

This module configures Celery for distributed task processing, enabling the API
to offload heavy feed processing tasks to background workers. This solves the
Vercel/Render timeout issues by keeping the API response instant while processing
continues asynchronously.

Architecture:
- Broker: Redis (fast, low-latency message queue)
- Backend: Redis (stores task results and state)
- Serializer: JSON (secure, human-readable)
- Workers: Can run on separate instances for horizontal scaling
"""

import os
from celery import Celery
from kombu import Queue

# ============================================================================
# CONFIGURATION
# ============================================================================

# Redis connection from environment variable
# Format: redis://localhost:6379/0 or redis://user:pass@host:port/db
REDIS_URL = os.getenv("REDIS_URL", "redis://localhost:6379/0")

# Celery broker and backend (both use Redis)
# Using separate Redis databases for better isolation:
# - DB 0: Message broker (task queue)
# - DB 1: Result backend (task results storage)
BROKER_URL = REDIS_URL
RESULT_BACKEND = REDIS_URL.replace("/0", "/1") if "/0" in REDIS_URL else f"{REDIS_URL}/1"


# ============================================================================
# CELERY APPLICATION INITIALIZATION
# ============================================================================

celery_app = Celery(
    "sentinel",
    broker=BROKER_URL,
    backend=RESULT_BACKEND,
    include=["tasks"]  # Auto-discover tasks from tasks.py
)

# ============================================================================
# CELERY CONFIGURATION
# ============================================================================

celery_app.conf.update(
    # ========================================================================
    # TASK EXECUTION SETTINGS
    # ========================================================================
    
    # Task serialization (JSON is secure, msgpack is faster but needs install)
    task_serializer="json",
    accept_content=["json"],
    result_serializer="json",
    timezone="UTC",
    enable_utc=True,
    
    # Task result expiration (1 hour - results auto-deleted after)
    # This prevents Redis from growing unbounded
    result_expires=3600,
    
    # Task acknowledgment - tasks are acknowledged AFTER execution
    # This ensures tasks are re-queued if worker crashes mid-execution
    task_acks_late=True,
    
    # Prefetch multiplier - how many tasks each worker reserves
    # Lower = better distribution, higher = better throughput
    # 1 = worker only takes next task after current one completes
    worker_prefetch_multiplier=1,
    
    # Task time limits (safety nets to prevent infinite loops)
    task_time_limit=3600,      # Hard limit: 1 hour (task killed)
    task_soft_time_limit=3300, # Soft limit: 55 min (SoftTimeLimitExceeded raised)
    
    # ========================================================================
    # RETRY CONFIGURATION
    # ========================================================================
    
    # Default retry policy for all tasks
    task_default_retry_delay=60,      # Wait 60 seconds before retry
    task_max_retries=3,                # Maximum 3 retry attempts
    
    # Exponential backoff for retries
    # Retry 1: 60s, Retry 2: 120s, Retry 3: 240s
    task_retry_backoff=True,
    task_retry_backoff_max=600,        # Max backoff: 10 minutes
    task_retry_jitter=True,            # Add random jitter to prevent thundering herd
    
    # ========================================================================
    # ROUTING AND QUEUES
    # ========================================================================
    
    # Define task queues with priorities
    task_queues=(
        # High priority: Critical tasks (e.g., user-triggered syncs)
        Queue("high_priority", routing_key="high"),
        
        # Default priority: Regular feed processing
        Queue("default", routing_key="default"),
        
        # Low priority: Background maintenance tasks
        Queue("low_priority", routing_key="low"),
    ),
    
    # Default queue for tasks
    task_default_queue="default",
    task_default_exchange="tasks",
    task_default_exchange_type="direct",
    task_default_routing_key="default",
    
    # ========================================================================
    # WORKER SETTINGS
    # ========================================================================
    
    # Worker concurrency (auto-detected based on CPU cores)
    # Override with: celery -A celery_app worker --concurrency=8
    worker_concurrency=None,  # None = auto (number of CPUs)
    
    # Worker pool implementation
    # - prefork: Multi-process (default, best for CPU-bound tasks)
    # - gevent: Coroutine-based (good for I/O-bound tasks like HTTP requests)
    # - eventlet: Alternative coroutine pool
    worker_pool="prefork",
    
    # Disable task events (reduces Redis traffic)
    # Enable only if using Flower monitoring dashboard
    worker_send_task_events=False,
    task_send_sent_event=False,
    
    # Worker shutdown behavior
    # Cancel long-running tasks on shutdown (vs waiting for completion)
    worker_cancel_long_running_tasks_on_connection_loss=True,
    
    # ========================================================================
    # RESULT BACKEND SETTINGS
    # ========================================================================
    
    # Store task results (needed for tracking task status)
    task_ignore_result=False,
    
    # Store task metadata (args, kwargs, traceback on failure)
    result_extended=True,
    
    # Compression for large results
    result_compression="gzip",
    
    # Backend options
    result_backend_transport_options={
        "master_name": "mymaster",  # For Redis Sentinel (if using HA setup)
        "visibility_timeout": 3600,  # 1 hour
    },
    
    # ========================================================================
    # MONITORING AND LOGGING
    # ========================================================================
    
    # Task tracking (allows querying task state)
    task_track_started=True,
    
    # Logging
    worker_log_format="[%(asctime)s: %(levelname)s/%(processName)s] %(message)s",
    worker_task_log_format="[%(asctime)s: %(levelname)s/%(processName)s][%(task_name)s(%(task_id)s)] %(message)s",
    
    # ========================================================================
    #BEAT SCHEDULER (for periodic tasks)
    # ========================================================================
    
    # Periodic task schedule (uncomment to enable scheduled tasks)
    # beat_schedule={
    #     "sync-all-feeds-hourly": {
    #         "task": "tasks.sync_all_feeds_task",
    #         "schedule": 3600.0,  # Every hour
    #     },
    # },
)


# ============================================================================
# TASK ROUTES (map tasks to specific queues)
# ============================================================================

celery_app.conf.task_routes = {
    # Feed processing tasks -> default queue
    "tasks.process_feed_chunk": {"queue": "default"},
    "tasks.sync_feed_task": {"queue": "default"},
    
    # Enrichment tasks -> high priority (user-facing)
    "tasks.enrich_ioc_task": {"queue": "high_priority"},
    
    # Maintenance tasks -> low priority
    "tasks.cleanup_old_iocs": {"queue": "low_priority"},
}


# ============================================================================
# HEALTH CHECK
# ============================================================================

@celery_app.task(bind=True, name="celery.ping")
def celery_ping(self):
    """
    Health check task to verify Celery workers are running.
    
    Usage:
        from celery_app import celery_ping
        result = celery_ping.delay()
        print(result.get(timeout=5))  # Should return "pong"
    """
    return "pong"


if __name__ == "__main__":
    # Allow running this file directly for debugging
    print(f"Celery App Configuration:")
    print(f"  Broker: {BROKER_URL}")
    print(f"  Backend: {RESULT_BACKEND}")
    print(f"  Queues: {[q.name for q in celery_app.conf.task_queues]}")
    print(f"\nTo start worker:")
    print(f"  celery -A celery_app worker --loglevel=info")
    print(f"\nTo start with concurrency:")
    print(f"  celery -A celery_app worker --concurrency=8 --loglevel=info")
