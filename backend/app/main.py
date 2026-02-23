"""SENTINEL Threat Intelligence Platform — FastAPI Application Entry Point."""

from contextlib import asynccontextmanager

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

import structlog

from app.config import settings
from app.api import api_router

logger = structlog.get_logger()


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Application startup and shutdown events."""
    logger.info(
        "sentinel_starting",
        environment=settings.ENVIRONMENT,
    )
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
