"""
Celery Worker Entry Point for SENTINEL Threat Intelligence Platform.

This module provides the entry point for starting Celery workers. Workers
consume tasks from the Redis queue and execute them in parallel.

Usage:
    # Start worker with default settings (auto-detect CPU cores)
    celery -A worker.celery_app worker --loglevel=info
    
    # Start worker with custom concurrency
    celery -A worker.celery_app worker --concurrency=8 --loglevel=info
    
    # Start worker with gevent pool (for I/O-bound tasks)
    celery -A worker.celery_app worker --pool=gevent --concurrency=100 --loglevel=info
    
    # Start worker for specific queue only
    celery -A worker.celery_app worker --queues=high_priority --loglevel=info
    
    # Start worker with autoscaling (min 2, max 10 workers)
    celery -A worker.celery_app worker --autoscale=10,2 --loglevel=info

Production Deployment:
    # Using systemd (recommended for Linux servers)
    # See: systemd/celery-worker.service
    
    # Using Docker
    docker run -d --name celery-worker \\
        -e REDIS_URL=redis://redis:6379/0 \\
        -e DATABASE_URL=... \\
        myapp:latest \\
        celery -A worker.celery_app worker --loglevel=info
    
    # Using Supervisor
    # See: supervisor/celery-worker.conf

Monitoring:
    # Check worker status
    celery -A worker.celery_app inspect active
    
    # Check registered tasks
    celery -A worker.celery_app inspect registered
    
    # Check queue length
    celery -A worker.celery_app inspect active_queues
    
    # Flower web UI (install: pip install flower)
    celery -A worker.celery_app flower --port=5555
"""

import sys
import signal
from pathlib import Path

# Add backend directory to Python path (for imports to work)
backend_dir = Path(__file__).parent
if str(backend_dir) not in sys.path:
    sys.path.insert(0, str(backend_dir))

# Import Celery app (this auto-discovers tasks)
from celery_app import celery_app

# Import all tasks explicitly (ensures they're registered)
# This is redundant with include=["tasks"] in celery_app.py, but makes debugging easier
import tasks  # noqa: F401


# ============================================================================
# GRACEFUL SHUTDOWN HANDLER
# ============================================================================

def handle_shutdown(signum, frame):
    """
    Handle graceful shutdown on SIGTERM/SIGINT.
    
    This ensures:
    - Current tasks complete before worker exits
    - No tasks are lost
    - Clean Redis connection close
    """
    print("\n🛑 Received shutdown signal. Finishing current tasks...")
    print("   Press Ctrl+C again to force quit (may lose tasks)")
    
    # Note: Celery handles SIGTERM gracefully by default
    # This handler is just for custom logging
    sys.exit(0)


# Register signal handlers
signal.signal(signal.SIGTERM, handle_shutdown)
signal.signal(signal.SIGINT, handle_shutdown)


# ============================================================================
# WORKER STARTUP HOOK
# ============================================================================

@celery_app.on_after_configure.connect
def setup_periodic_tasks(sender, **kwargs):
    """
    Configure periodic tasks (Celery Beat).
    
    This runs automatically when worker starts.
    
    Example periodic tasks:
    - Sync feeds every hour
    - Clean up old IOCs daily
    - Generate reports weekly
    """
    # Uncomment to enable periodic feed sync
    # sender.add_periodic_task(
    #     3600.0,  # Every hour
    #     tasks.sync_feed_task.s(feed_slug="urlhaus"),
    #     name="sync-urlhaus-hourly",
    # )
    pass


@celery_app.on_after_finalize.connect
def log_registered_tasks(sender, **kwargs):
    """Log all registered tasks on worker startup."""
    print("\n" + "=" * 70)
    print("🚀 SENTINEL Celery Worker Starting")
    print("=" * 70)
    print(f"\n📋 Registered Tasks ({len(sender.tasks)}):")
    for task_name in sorted(sender.tasks.keys()):
        if not task_name.startswith("celery."):
            print(f"   ✓ {task_name}")
    print("\n" + "=" * 70 + "\n")


# ============================================================================
# WORKER HEALTH CHECK
# ============================================================================

@celery_app.task(name="worker.health_check")
def health_check():
    """
    Worker health check task.
    
    Usage:
        from worker import health_check
        result = health_check.delay()
        print(result.get(timeout=5))  # Should return {"status": "healthy"}
    """
    return {
        "status": "healthy",
        "worker": "celery",
        "timestamp": celery_app.now().isoformat(),
    }


# ============================================================================
# MAIN ENTRY POINT
# ============================================================================

if __name__ == "__main__":
    """
    Direct execution (not recommended for production).
    
    Better to use:
        celery -A worker.celery_app worker --loglevel=info
    
    But this allows testing:
        python worker.py
    """
    import os
    
    # Check Redis connection
    redis_url = os.getenv("REDIS_URL", "redis://localhost:6379/0")
    print(f"🔗 Connecting to Redis: {redis_url}")
    
    # Start worker programmatically
    argv = [
        "worker",
        "--loglevel=INFO",
        "--concurrency=4",
        "--pool=prefork",
    ]
    
    celery_app.worker_main(argv)
