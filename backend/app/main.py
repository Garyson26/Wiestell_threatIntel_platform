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
    logger.info("sentinel_starting", environment=settings.ENVIRONMENT)

    # Start the periodic feed scheduler
    scheduler_task = asyncio.create_task(feed_scheduler_loop())
    logger.info("feed_scheduler_registered")

    yield

    # Gracefully cancel the scheduler on shutdown
    scheduler_task.cancel()
    try:
        await scheduler_task
    except asyncio.CancelledError:
        pass
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


@app.get("/api/v1/health")
async def health_check():
    """Health check endpoint for Docker and monitoring."""
    return {
        "status": "healthy",
        "service": "sentinel-api",
        "version": "1.0.0",
    }
