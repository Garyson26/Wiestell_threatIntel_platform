"""SENTINEL Threat Intelligence Platform — FastAPI Application Entry Point."""

import traceback
import uuid
from contextlib import asynccontextmanager

import structlog
from fastapi import Depends, FastAPI, Request, status
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse

from app.api import api_router
from app.api.deps import require_admin
from app.config import settings
from app.utils.email_service import send_error_alert_email
from app.utils.sanitize import redact_headers, redact_secrets

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


# Interactive docs publish the full attack surface, so they are served only when
# explicitly enabled (development, or ENABLE_API_DOCS=true).
_docs = settings.docs_enabled

app = FastAPI(
    title="SENTINEL — Threat Intelligence Platform",
    description=(
        "Open-source threat intelligence platform that aggregates, enriches, "
        "and scores IOCs from multiple feeds."
    ),
    version="1.0.0",
    docs_url="/docs" if _docs else None,
    redoc_url="/redoc" if _docs else None,
    openapi_url="/openapi.json" if _docs else None,
    lifespan=lifespan,
)

# ── CORS ──────────────────────────────────────────────────────────────────────
# A wildcard origin combined with allow_credentials lets any site read
# authenticated responses, so only an explicit origin list is ever installed.
cors_origins = settings.cors_origin_list
if not cors_origins:
    logger.warning("cors_no_origins_configured", hint="Set CORS_ORIGINS to your frontend origin(s)")

app.add_middleware(
    CORSMiddleware,
    allow_origins=cors_origins,
    allow_credentials=True,
    allow_methods=["GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"],
    allow_headers=["Authorization", "Content-Type", "X-Cron-Secret"],
    max_age=600,
)


@app.middleware("http")
async def security_headers_middleware(request: Request, call_next):
    """Attach baseline hardening headers to every API response."""
    response = await call_next(request)
    response.headers.setdefault("X-Content-Type-Options", "nosniff")
    response.headers.setdefault("X-Frame-Options", "DENY")
    response.headers.setdefault("Referrer-Policy", "no-referrer")
    response.headers.setdefault("Cache-Control", "no-store")
    response.headers.setdefault(
        "Content-Security-Policy",
        "default-src 'none'; frame-ancestors 'none'; base-uri 'none'"
        if not _docs
        # /docs needs to load its own bundle and inline bootstrap script.
        else "default-src 'self' https://cdn.jsdelivr.net; img-src 'self' data: https://fastapi.tiangolo.com; "
             "style-src 'self' 'unsafe-inline' https://cdn.jsdelivr.net; script-src 'self' 'unsafe-inline' https://cdn.jsdelivr.net; "
             "frame-ancestors 'none'; base-uri 'none'",
    )
    if settings.is_production:
        response.headers.setdefault(
            "Strict-Transport-Security", "max-age=31536000; includeSubDomains"
        )
    return response


@app.middleware("http")
async def error_notification_middleware(request: Request, call_next):
    """Catch unhandled exceptions, alert the admin, and return an opaque error."""
    try:
        return await call_next(request)
    except Exception as exc:
        error_id = uuid.uuid4().hex[:12]
        error_type = type(exc).__name__
        endpoint = str(request.url.path)
        method = request.method

        # Full detail goes to the log only — never to the HTTP response.
        logger.error(
            "unhandled_exception",
            error_id=error_id,
            error_type=error_type,
            error_message=redact_secrets(exc),
            endpoint=endpoint,
            method=method,
            exc_info=True,
        )

        try:
            request_data = {
                "method": method,
                "url": redact_secrets(request.url),
                "client": request.client.host if request.client else "unknown",
                # Authorization/cookie values are masked so an alert email never
                # carries a usable session token out of the platform.
                "headers": redact_headers(dict(request.headers)),
                "error_id": error_id,
            }
            send_error_alert_email(
                error_type=f"{status.HTTP_500_INTERNAL_SERVER_ERROR} {error_type}",
                error_message=redact_secrets(exc),
                endpoint=endpoint,
                method=method,
                traceback_info=redact_secrets(traceback.format_exc()),
                request_data=request_data,
            )
        except Exception as email_error:
            logger.warning("failed_to_send_error_email", error=str(email_error))

        return JSONResponse(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            content={
                "detail": "Internal server error",
                # Correlates the client report with the server log without
                # disclosing the exception type, message or stack trace.
                "error_id": error_id,
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
    """Readiness probe for Docker and uptime monitoring.

    Reports database reachability so an orchestrator can restart a broken
    container, but does not disclose the environment name or any error text.
    """
    from datetime import datetime, timezone

    from sqlalchemy import text

    health_status = {
        "status": "healthy",
        "service": "sentinel-api",
        "version": "1.0.0",
        "timestamp": datetime.now(timezone.utc).isoformat(),
    }

    try:
        from app.database import AsyncSessionLocal

        async with AsyncSessionLocal() as session:
            await session.execute(text("SELECT 1"))
        health_status["database"] = "connected"
    except Exception as e:
        logger.warning("health_check_db_error", error=redact_secrets(e))
        health_status["database"] = "disconnected"
        health_status["status"] = "degraded"

    return health_status


@app.get("/api/v1/cron-status", dependencies=[Depends(require_admin)])
async def cron_status():
    """Feed sync status and cron configuration. Admin only.

    Reports which feeds are enabled, when they last synced, and which are
    overdue. Sync error text is redacted because driver errors can embed the
    database connection URI.
    """
    from datetime import datetime

    from sqlalchemy import select

    from app.database import AsyncSessionLocal
    from app.models.feed import FeedSource

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
                "last_error": redact_secrets(feed.last_sync_error) if feed.last_sync_error else None,
                "ioc_count": feed.ioc_count,
            })

    enabled_count = sum(1 for f in feed_status if f["enabled"])
    overdue_count = sum(1 for f in feed_status if f["enabled"] and f["overdue"])

    return {
        "status": "ok",
        "timestamp": now.strftime("%Y-%m-%d %H:%M:%S UTC"),
        "scheduler_mode": "external_cron",
        "cron_endpoint": "/api/v1/feeds/sync-all",
        "background_scheduler": "disabled (serverless incompatible)",
        "total_feeds": len(feed_status),
        "enabled_feeds": enabled_count,
        "overdue_feeds": overdue_count,
        "feeds": feed_status,
        "note": (
            "Trigger a sync with POST /api/v1/feeds/sync-all using an admin token "
            "or the X-Cron-Secret header."
        ),
    }
