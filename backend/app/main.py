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


# Truthy spellings accepted for the override, in one place so the startup refusal and the
# /cron-status degradation report cannot drift apart.
_TRUTHY = {"1", "true", "yes"}


def _multiple_workers_allowed() -> bool:
    import os

    return (os.getenv("ALLOW_MULTIPLE_WORKERS") or "").strip().lower() in _TRUTHY


def _resolved_worker_count() -> int:
    """How many workers the server will ACTUALLY start, resolved the way uvicorn does.

    **The argv flag is not the whole story.** Verified against the installed
    ``uvicorn==0.34.0`` (``uvicorn/config.py:329-330``)::

        if workers is None and "WEB_CONCURRENCY" in os.environ:
            self.workers = int(os.environ["WEB_CONCURRENCY"])

    so dropping ``--workers 1`` from the start command and setting ``WEB_CONCURRENCY=4`` in
    Render's dashboard starts four workers. The first version of this guard read ``sys.argv``
    only, so that combination passed silently *and* reported no degradation — the exact
    "guard whose failure mode is silence" class the CLAUDE.md rule names, in the change that
    added the rule's newest application (finding R-04, 2026-08-04).

    **The full set was enumerated rather than guessed.** Every ``os.environ`` read in the
    installed uvicorn is: ``WEB_CONCURRENCY`` (worker count), ``FORWARDED_ALLOW_IPS`` (proxy
    trust, unrelated to counting) and an env-file path. There is no ``-w`` short form.
    gunicorn is **not installed** and is not a start path here — it would add
    ``GUNICORN_CMD_ARGS`` as a second injection point, which is why
    ``tests/test_process_model.py`` fails if it appears in any start command.

    Precedence matches uvicorn's: an explicit flag wins, the environment is the fallback.
    """
    import os
    import sys

    requested = None
    argv = sys.argv
    for i, arg in enumerate(argv):
        if arg == "--workers" and i + 1 < len(argv):
            requested = argv[i + 1]
        elif arg.startswith("--workers="):
            requested = arg.split("=", 1)[1]

    # Only consult the environment when no flag was given — uvicorn's own precedence.
    if requested is None:
        requested = os.getenv("WEB_CONCURRENCY")

    try:
        return int(requested) if requested is not None else 1
    except (TypeError, ValueError):
        # Not our business to validate the server's own argument parsing.
        return 1


def _assert_single_worker() -> None:
    """Refuse to start under multiple uvicorn workers unless explicitly overridden.

    **Why this is a runtime check and not only a test.** `tests/test_process_model.py`
    asserts that `render.yaml` and `start.sh` pass `--workers 1`, but that guards the
    *repository*, not the *deployment*. Render's dashboard allows a start-command override
    that lives in no file; so does `docker run` with different arguments, or a developer
    debugging with `--workers 4` and carrying the command forward. None of those touch a
    file the test can read.

    Five subsystems assume one process per instance, and each breaks quietly rather than
    loudly at N workers:

      1. `utils/rate_limiter` falls back to per-process state without ``REDIS_URL``, so N
         workers give N independent budgets and the effective limit is
         N x ``AUTH_RATE_LIMIT_MAX`` (SECURITY_REVIEW.md residual risk #5);
      2. `database.py`'s pool is per process, so ``pool_size=2 + max_overflow=3`` becomes
         5N connections against a **shared** MySQL account allowance;
      3. `enrichment_engine`'s semaphore is module-level, so the real in-flight ceiling
         becomes 5N third-party calls;
      4. any in-process cache would become N caches serving inconsistent reads;
      5. ``REDIS_URL`` is deliberately unset, so the limiter's process-local fallback is
         load-bearing — at N workers a shared store becomes required rather than optional.

    Failing closed is deliberate: every one of those degrades silently, and (2) can exhaust
    an allowance shared with other clients — a failure that lands outside this application.
    ``ALLOW_MULTIPLE_WORKERS=true`` opens the door for someone who has actually revisited
    all four, and says so in the logs when they do.

    Worker children **do** inherit ``sys.argv`` — verified empirically 2026-07-31 against
    uvicorn on Windows (spawn, the harder case: each worker re-executes and still sees the
    parent's argv), so this fires in every worker rather than only the supervisor.
    """
    count = _resolved_worker_count()
    if count <= 1:
        return

    override = _multiple_workers_allowed()
    detail = (
        f"{count} uvicorn workers requested. Four subsystems assume one process per "
        "instance: the in-memory rate limiter (N independent budgets), the database pool "
        "(5N connections against a shared account allowance), the enrichment semaphore "
        "(5N third-party calls in flight), and any in-process cache. See "
        "app/main.py::_assert_single_worker and SECURITY_REVIEW.md residual risk #5."
    )
    if override:
        logger.warning("multiple_workers_allowed", workers=count, detail=detail)
        return
    logger.error("multiple_workers_refused", workers=count, detail=detail)
    raise RuntimeError(
        detail + " Set ALLOW_MULTIPLE_WORKERS=true to override once all four have been "
        "revisited."
    )


_assert_single_worker()



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


def _deployment_degradations() -> list:
    """States where the app runs but is not doing what the design assumes.

    **ADMIN-ONLY, deliberately.** This was briefly on the public ``/health`` payload, which
    was a poor trade: ``/health`` must stay unauthenticated for Render's health checker, so
    anything on it is world-readable, and ``multiple_workers_allowed`` tells an
    unauthenticated reader that the login rate limit is N times weaker than it appears —
    exactly the fact worth knowing before starting a credential-stuffing run. Publishing
    one's own mitigation gap for post-deploy convenience is not a trade worth making.
    (GeoIP absence is harmless recon by comparison, but there is no reason to split them.)

    Both states are settable in Render's dashboard and invisible in the repository, so no
    test can see them and the only other evidence is a boot log line that scrolls away —
    which is why they are surfaced at all.
    """
    import os

    degradations = []

    # The .mmdb is fetched by a build step that cannot fail the build
    # (`|| echo "...continuing"`), so its absence is silent and costs country/ASN
    # enrichment for the ENTIRE IP population. See PROJECT_SUMMARY.md §8 item 14.
    try:
        from app.enrichers import _geoip_database_available

        if not _geoip_database_available():
            degradations.append({
                "id": "geoip_database_missing",
                "impact": "IP indicators are enriched without country or ASN data",
                "fix": "set MAXMIND_ACCOUNT_ID and MAXMIND_LICENSE_KEY, then redeploy",
            })
    except Exception as e:  # pragma: no cover - never let a probe break the probe
        logger.warning("degradation_probe_geoip_error", error=redact_secrets(e))

    # The override exists for someone who has revisited all four single-process
    # assumptions. If it was set merely to get past a refused boot, the rate limiter,
    # connection pool, enrichment bound and any cache are all degraded and nothing else
    # says so. See main.py::_assert_single_worker.
    workers = _resolved_worker_count()
    if workers > 1 and not _multiple_workers_allowed():
        # Startup should have refused this, so reaching it means the refusal was bypassed
        # or the count changed after import. Report it as its own state rather than
        # folding it into the override case.
        degradations.append({
            "id": "multiple_workers_undeclared",
            "impact": (
                f"{workers} workers are running without ALLOW_MULTIPLE_WORKERS set, so "
                "the startup refusal did not fire and every per-process assumption is "
                "silently multiplied"
            ),
            "fix": "run one worker, or set ALLOW_MULTIPLE_WORKERS=true deliberately",
        })
    if _multiple_workers_allowed():
        degradations.append({
            "id": "multiple_workers_allowed",
            "impact": (
                "rate limits are per worker, the DB pool is 5 connections per worker "
                "against a shared allowance, enrichment concurrency is 5 per worker, "
                "and any in-process cache is per worker"
            ),
            "fix": (
                "unset ALLOW_MULTIPLE_WORKERS and run one worker, or provision Redis "
                "and re-tune pool_size and ENRICHMENT_CONCURRENCY"
            ),
        })

    return degradations


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
        # Empty on a correct deployment. Lives here rather than on /health because
        # /health is public and one of these entries discloses a weakened rate limit —
        # see _deployment_degradations. This endpoint already exists to report
        # operational state and is already admin-gated, so it is the natural home.
        "degradations": _deployment_degradations(),
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
