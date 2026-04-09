"""SENTINEL Threat Intelligence Platform — FastAPI Application Entry Point."""

import asyncio
import os
from contextlib import asynccontextmanager

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

import structlog

from app.config import settings
from app.api import api_router
from app.services.feed_scheduler import feed_scheduler_loop

logger = structlog.get_logger()


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Application startup and shutdown events."""
    logger.info("sentinel_starting", environment=settings.ENVIRONMENT)

    # On Vercel (serverless), background tasks don't persist between invocations.
    # Use Vercel Cron Jobs instead (configured in vercel.json).
    # Only start the scheduler for long-running deployments (Railway, Docker, etc.)
    is_serverless = os.getenv("VERCEL") or os.getenv("AWS_LAMBDA_FUNCTION_NAME")
    
    scheduler_task = None
    if not is_serverless:
        # Start the periodic feed scheduler for persistent deployments
        scheduler_task = asyncio.create_task(feed_scheduler_loop())
        logger.info("feed_scheduler_registered")
    else:
        logger.info("serverless_detected", message="Feed scheduler disabled. Use Vercel Cron or manual sync.")

    yield

    # Gracefully cancel the scheduler on shutdown
    if scheduler_task:
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
