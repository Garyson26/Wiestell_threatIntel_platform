"""Celery application configuration."""

from celery import Celery
from celery.schedules import crontab

from app.config import settings

celery_app = Celery(
    "sentinel",
    broker=settings.REDIS_URL,
    backend=settings.REDIS_URL,
    include=[
        "app.tasks.feed_tasks",
        "app.tasks.enrichment_tasks",
    ],
)

celery_app.conf.update(
    task_serializer="json",
    accept_content=["json"],
    result_serializer="json",
    timezone="UTC",
    enable_utc=True,
    task_track_started=True,
    task_acks_late=True,
    worker_prefetch_multiplier=1,
    task_soft_time_limit=300,
    task_time_limit=600,
)

# Periodic task schedule
celery_app.conf.beat_schedule = {
    "sync-all-feeds-hourly": {
        "task": "app.tasks.feed_tasks.sync_all_feeds",
        "schedule": crontab(minute=0),  # Every hour
    },
    "sync-critical-feeds": {
        "task": "app.tasks.feed_tasks.sync_critical_feeds",
        "schedule": crontab(minute="*/15"),  # Every 15 minutes
    },
}
