"""SENTINEL Threat Intelligence Platform — FastAPI Application Entry Point."""

import asyncio
import traceback
from contextlib import asynccontextmanager

from fastapi import FastAPI, Request, status
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse

import structlog

from app.config import settings
from app.api import api_router
from app.services.feed_scheduler import feed_scheduler_loop
from app.utils.email_service import send_error_alert_email

logger = structlog.get_logger()


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Application startup and shutdown events."""
    logger.info("sentinel_starting", environment=settings.ENVIRONMENT, platform="vercel-serverless")
    
    # Background scheduler disabled for Vercel serverless
    # Use Vercel Cron instead: /api/v1/feeds/sync-all (configured in vercel.json)
    logger.info("feed_scheduler_mode", mode="vercel_cron", endpoint="/api/v1/feeds/sync-all")
    
    yield
    
    logger.info("sentinel_shutting_down")


app = FastAPI(
    title="SENTINEL — Threat Intelligence Platform",
    description=(
        "Open-source threat intelligence platform that aggregates, enriches, "
        "and scores IOCs from multiple feeds."
    ),
    version="1.0.0",
    docs_url="/docs",
    redoc_url="/redoc",
    lifespan=lifespan,
)

# CORS middleware
cors_origins = (
    ["*"] if settings.CORS_ORIGINS == "*"
    else [o.strip() for o in settings.CORS_ORIGINS.split(",")]
)
app.add_middleware(
    CORSMiddleware,
    allow_origins=cors_origins,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


# Global exception handler middleware
@app.middleware("http")
async def error_notification_middleware(request: Request, call_next):
    """Catch unhandled exceptions and send email alerts."""
    try:
        response = await call_next(request)
        return response
    except Exception as exc:
        # Get error details
        error_type = type(exc).__name__
        error_message = str(exc)
        endpoint = str(request.url.path)
        method = request.method
        traceback_info = traceback.format_exc()
        
        # Log the error
        logger.error(
            "unhandled_exception",
            error_type=error_type,
            error_message=error_message,
            endpoint=endpoint,
            method=method,
        )
        
        # Send email alert (non-blocking, errors won't crash the app)
        try:
            request_data = {
                "method": method,
                "url": str(request.url),
                "client": request.client.host if request.client else "unknown",
                "headers": dict(request.headers),
            }
            
            send_error_alert_email(
                error_type=f"{status.HTTP_500_INTERNAL_SERVER_ERROR} {error_type}",
                error_message=error_message,
                endpoint=endpoint,
                method=method,
                traceback_info=traceback_info,
                request_data=request_data,
            )
        except Exception as email_error:
            logger.warning("failed_to_send_error_email", error=str(email_error))
        
        # Return error response to client
        return JSONResponse(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            content={
                "detail": "Internal server error",
                "error_type": error_type,
                "message": error_message if settings.ENVIRONMENT == "development" else "An unexpected error occurred",
            },
        )


# Register API routes
app.include_router(api_router)


@app.api_route("/", methods=["GET", "HEAD"])
async def root():
    """Root endpoint - simple health check for Render (supports GET and HEAD)."""
    return {"status": "ok", "service": "sentinel-api"}


@app.api_route("/health", methods=["GET", "HEAD"])
async def health_root():
    """Simple health check at root level for Render (supports GET and HEAD)."""
    return {"status": "healthy", "service": "sentinel-api", "version": "1.0.0"}


@app.api_route("/api/v1/health", methods=["GET", "HEAD"])
async def health_check():
    """Detailed health check endpoint for Docker and monitoring (supports GET and HEAD)."""
    from datetime import datetime
    
    health_status = {
        "status": "healthy",
        "service": "sentinel-api",
        "version": "1.0.0",
        "timestamp": datetime.utcnow().isoformat(),
        "environment": settings.ENVIRONMENT,
    }
    
    # Optional: Check database connectivity
    try:
        from app.database import AsyncSessionLocal
        from sqlalchemy import text
        
        async with AsyncSessionLocal() as session:
            await session.execute(text("SELECT 1"))
            health_status["database"] = "connected"
    except Exception as e:
        logger.warning("health_check_db_error", error=str(e))
        health_status["database"] = "disconnected"
        health_status["status"] = "degraded"
    
    return health_status


@app.get("/api/v1/cron-status")
async def cron_status():
    """
    Check feed sync status and cron configuration.
    
    Use this endpoint to verify:
    - Which feeds are enabled
    - When feeds were last synced
    - Which feeds are overdue for sync
    - Vercel Cron configuration status
    """
    from datetime import datetime
    from app.database import AsyncSessionLocal
    from app.models.feed import FeedSource
    from sqlalchemy import select
    
    async with AsyncSessionLocal() as session:
        result = await session.execute(
            select(FeedSource).order_by(FeedSource.is_enabled.desc(), FeedSource.name)
        )
        feeds = result.scalars().all()
        
        now = datetime.utcnow()
        feed_status = []
        
        for feed in feeds:
            freq = feed.sync_frequency or 3600
            last = feed.last_sync_at
            overdue = last is None or (now - last).total_seconds() >= freq
            
            seconds_since = int((now - last).total_seconds()) if last else None
            next_sync_in = max(0, freq - seconds_since) if seconds_since is not None else 0
            
            feed_status.append({
                "name": feed.name,
                "slug": feed.slug,
                "enabled": feed.is_enabled,
                "last_sync": last.strftime("%Y-%m-%d %H:%M:%S UTC") if last else "never",
                "seconds_since_last_sync": seconds_since,
                "sync_frequency": freq,
                "next_sync_in_seconds": next_sync_in,
                "overdue": overdue,
                "last_status": feed.last_sync_status,
                "last_error": feed.last_sync_error,
                "ioc_count": feed.ioc_count,
            })
    
    enabled_count = sum(1 for f in feed_status if f["enabled"])
    overdue_count = sum(1 for f in feed_status if f["enabled"] and f["overdue"])
    
    return {
        "status": "ok",
        "timestamp": now.strftime("%Y-%m-%d %H:%M:%S UTC"),
        "platform": "vercel-serverless",
        "scheduler_mode": "vercel_cron",
        "cron_enabled": True,
        "cron_schedule": "0 * * * * (every hour)",
        "cron_endpoint": "/api/v1/feeds/sync-all",
        "background_scheduler": "disabled (serverless incompatible)",
        "total_feeds": len(feeds),
        "enabled_feeds": enabled_count,
        "overdue_feeds": overdue_count,
        "feeds": feed_status,
        "note": "Feeds sync automatically every hour via Vercel Cron. Manual sync: POST /api/v1/feeds/sync-all",
    }
