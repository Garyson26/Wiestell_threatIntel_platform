"""Enrichment API endpoints."""

from datetime import datetime, timezone
from typing import Literal, Optional

from fastapi import APIRouter, BackgroundTasks, Depends, HTTPException, Query
from pydantic import BaseModel
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

import structlog

from app.database import AsyncSessionLocal, get_db
from app.models.enrichment import Enrichment
from app.models.ioc import IOC
from app.schemas.enrichment import EnrichmentRequest, EnrichmentResponse
from app.services.enrichment_engine import _get_applicable_sources, enrich_ioc

logger = structlog.get_logger()

router = APIRouter()

# ── live backfill state (in-process; reset on each new run) ─────────────────
_backfill_running: bool = False
_backfill_stats: dict = {
    "started_at": None,
    "to_process": 0,
    "done": 0,
    "success": 0,
    "skipped": 0,
    "failed": 0,
    "current_ioc": None,
    "elapsed_sec": 0.0,
}


def _utcnow() -> datetime:
    return datetime.now(timezone.utc).replace(tzinfo=None)


# ── Response schemas ──────────────────────────────────────────────────────────

class BackfillStatsSnapshot(BaseModel):
    started_at: Optional[str]
    to_process: int
    done: int
    success: int
    skipped: int
    failed: int
    current_ioc: Optional[str]
    elapsed_sec: float
    percent_complete: float


class BackfillStatusResponse(BaseModel):
    total_iocs: int
    unenriched_iocs: int
    backfill_running: bool
    live_stats: Optional[BackfillStatsSnapshot] = None


class BackfillStartResponse(BaseModel):
    status: Literal["queued", "already_running"]
    message: str
    unenriched_iocs: int
    limit: Optional[int]
    ioc_type: Optional[str]
    force: bool


# ── Bulk backfill endpoints (registered BEFORE wildcard /{ioc_id} routes) ────

@router.get("/backfill/status", response_model=BackfillStatusResponse)
async def backfill_status(
    ioc_type: Optional[str] = Query(
        None,
        description="Filter counts to a specific IOC type (ip, domain, url, hash, email, cve)",
    ),
):
    """
    Return counts of total IOCs and how many still have no enrichment data.

    Use this to gauge progress before or during a backfill run.
    """
    async with AsyncSessionLocal() as session:
        total_q = select(func.count(IOC.id))
        unenriched_q = (
            select(func.count(IOC.id))
            .outerjoin(Enrichment, IOC.id == Enrichment.ioc_id)
            .where(Enrichment.id.is_(None))
        )
        if ioc_type:
            total_q = total_q.where(IOC.type == ioc_type)
            unenriched_q = unenriched_q.where(IOC.type == ioc_type)

        total = (await session.execute(total_q)).scalar_one()
        unenriched = (await session.execute(unenriched_q)).scalar_one()

    live: Optional[BackfillStatsSnapshot] = None
    if _backfill_running:
        s = _backfill_stats
        to_proc = s["to_process"] or 1
        live = BackfillStatsSnapshot(
            started_at=s["started_at"],
            to_process=s["to_process"],
            done=s["done"],
            success=s["success"],
            skipped=s["skipped"],
            failed=s["failed"],
            current_ioc=s["current_ioc"],
            elapsed_sec=round((_utcnow() - _backfill_stats["_start_dt"]).total_seconds(), 1)
            if _backfill_stats.get("_start_dt") else 0.0,
            percent_complete=round(s["done"] / to_proc * 100, 1),
        )

    return BackfillStatusResponse(
        total_iocs=total,
        unenriched_iocs=unenriched,
        backfill_running=_backfill_running,
        live_stats=live,
    )


@router.post("/backfill/start", status_code=202, response_model=BackfillStartResponse)
async def backfill_start(
    background_tasks: BackgroundTasks,
    limit: Optional[int] = Query(
        None,
        ge=1,
        le=50000,
        description="Maximum number of IOCs to enrich. Omit to process all unenriched IOCs.",
    ),
    ioc_type: Optional[str] = Query(
        None,
        description="Only enrich IOCs of this type (ip, domain, url, hash, email, cve).",
    ),
    force: bool = Query(
        False,
        description="Re-enrich IOCs that already have enrichment data.",
    ),
):
    """
    Start a background enrichment backfill.

    Finds every IOC that has **no enrichment data** in the database and fetches
    enrichment from all applicable sources (GeoIP, WHOIS, DNS, reputation,
    Shodan, MalwareBazaar).  Each IOC is committed individually so progress is
    saved continuously even if the process is interrupted.

    Returns **202 Accepted** immediately; actual work runs in the background.
    Only one backfill job runs at a time — call `/backfill/status` to monitor
    progress.

    **Examples**
    - Enrich all unenriched IOCs: `POST /api/v1/enrichment/backfill/start`
    - Only IP addresses, first 1 000: `?ioc_type=ip&limit=1000`
    - Force refresh all: `?force=true&limit=500`
    """
    global _backfill_running

    if _backfill_running:
        # Count so the caller knows how much is left
        async with AsyncSessionLocal() as session:
            q = (
                select(func.count(IOC.id))
                .outerjoin(Enrichment, IOC.id == Enrichment.ioc_id)
                .where(Enrichment.id.is_(None))
            )
            if ioc_type:
                q = q.where(IOC.type == ioc_type)
            unenriched = (await session.execute(q)).scalar_one()

        return BackfillStartResponse(
            status="already_running",
            message="A backfill is already in progress. Check /backfill/status for progress.",
            unenriched_iocs=unenriched,
            limit=limit,
            ioc_type=ioc_type,
            force=force,
        )

    # Count unenriched before queueing so we can return it in the response
    async with AsyncSessionLocal() as session:
        q = (
            select(func.count(IOC.id))
            .outerjoin(Enrichment, IOC.id == Enrichment.ioc_id)
            .where(Enrichment.id.is_(None))
        )
        if not force and ioc_type:
            q = q.where(IOC.type == ioc_type)
        unenriched = (await session.execute(q)).scalar_one()

    background_tasks.add_task(
        _run_backfill,
        limit=limit,
        ioc_type=ioc_type,
        force=force,
    )

    logger.info(
        "enrichment_backfill_queued",
        unenriched=unenriched,
        limit=limit,
        ioc_type=ioc_type,
        force=force,
    )

    return BackfillStartResponse(
        status="queued",
        message=(
            f"Backfill started in background. "
            f"{min(unenriched, limit) if limit else unenriched:,} IOC(s) will be enriched. "
            "Poll /api/v1/enrichment/backfill/status to monitor progress."
        ),
        unenriched_iocs=unenriched,
        limit=limit,
        ioc_type=ioc_type,
        force=force,
    )


# ── Background worker ─────────────────────────────────────────────────────────

async def _run_backfill(
    limit: Optional[int],
    ioc_type: Optional[str],
    force: bool,
) -> None:
    """Background task: fetch and store enrichment for all unenriched IOCs."""
    global _backfill_running, _backfill_stats
    _backfill_running = True

    BATCH = 50
    done = 0
    success = 0
    skipped = 0
    failed = 0
    offset = 0
    start = _utcnow()

    # ── Compute total to process for accurate progress % ─────────────────────
    try:
        async with AsyncSessionLocal() as session:
            if force:
                count_q = select(func.count(IOC.id))
            else:
                count_q = (
                    select(func.count(IOC.id))
                    .outerjoin(Enrichment, IOC.id == Enrichment.ioc_id)
                    .where(Enrichment.id.is_(None))
                )
            if ioc_type:
                count_q = count_q.where(IOC.type == ioc_type)
            total_to_process = (await session.execute(count_q)).scalar_one()
    except Exception:
        total_to_process = 0

    to_process = min(limit, total_to_process) if limit else total_to_process

    # Initialise live stats
    _backfill_stats = {
        "started_at": start.isoformat(),
        "_start_dt": start,
        "to_process": to_process,
        "done": 0,
        "success": 0,
        "skipped": 0,
        "failed": 0,
        "current_ioc": None,
        "elapsed_sec": 0.0,
    }

    logger.info(
        "backfill_started",
        to_process=to_process,
        limit=limit,
        ioc_type=ioc_type or "all",
        force=force,
    )

    try:
        while True:
            if to_process and done >= to_process:
                break

            fetch_size = BATCH if not to_process else min(BATCH, to_process - done)

            # ── Fetch next batch ──────────────────────────────────────────────
            async with AsyncSessionLocal() as session:
                if force:
                    q = select(IOC.id, IOC.type, IOC.value).order_by(IOC.id)
                else:
                    q = (
                        select(IOC.id, IOC.type, IOC.value)
                        .outerjoin(Enrichment, IOC.id == Enrichment.ioc_id)
                        .where(Enrichment.id.is_(None))
                        .order_by(IOC.id)
                    )
                if ioc_type:
                    q = q.where(IOC.type == ioc_type)
                q = q.offset(offset if force else 0).limit(fetch_size)
                rows = (await session.execute(q)).fetchall()

            if not rows:
                logger.info("backfill_no_more_rows", done=done)
                break

            batch_num = done // BATCH + 1
            logger.info(
                "backfill_batch_start",
                batch=batch_num,
                batch_size=len(rows),
                done_so_far=done,
                to_process=to_process,
            )

            # ── Process each IOC in the batch ────────────────────────────────
            for row in rows:
                ioc_id, ioc_type_val, ioc_value = str(row[0]), row[1], row[2]
                done += 1

                # Update live stats
                _backfill_stats["done"] = done
                _backfill_stats["current_ioc"] = f"{ioc_type_val}:{ioc_value}"

                applicable = _get_applicable_sources(ioc_type_val)
                if not applicable:
                    skipped += 1
                    _backfill_stats["skipped"] = skipped
                    logger.debug(
                        "backfill_ioc_skipped",
                        reason="no_applicable_sources",
                        ioc_type=ioc_type_val,
                        ioc_value=ioc_value,
                    )
                    continue

                logger.debug(
                    "backfill_ioc_enriching",
                    ioc_id=ioc_id,
                    ioc_type=ioc_type_val,
                    ioc_value=ioc_value,
                    sources=applicable,
                    progress=f"{done}/{to_process}",
                )

                try:
                    async with AsyncSessionLocal() as session:
                        result = await session.execute(
                            select(IOC).where(IOC.id == ioc_id)
                        )
                        ioc = result.scalar_one_or_none()
                        if not ioc:
                            skipped += 1
                            _backfill_stats["skipped"] = skipped
                            logger.warning("backfill_ioc_not_found", ioc_id=ioc_id)
                            continue

                        enrichments = await enrich_ioc(session, ioc)
                        await session.commit()

                    if enrichments:
                        success += 1
                        _backfill_stats["success"] = success
                        logger.debug(
                            "backfill_ioc_enriched",
                            ioc_id=ioc_id,
                            ioc_value=ioc_value,
                            sources_stored=[e.get("source") for e in enrichments],
                        )
                    else:
                        skipped += 1
                        _backfill_stats["skipped"] = skipped
                        logger.debug(
                            "backfill_ioc_no_data",
                            ioc_id=ioc_id,
                            ioc_value=ioc_value,
                        )

                except Exception as exc:
                    failed += 1
                    _backfill_stats["failed"] = failed
                    logger.warning(
                        "backfill_ioc_failed",
                        ioc_id=ioc_id,
                        ioc_type=ioc_type_val,
                        ioc_value=ioc_value,
                        error=str(exc),
                    )

            # ── Batch summary log every 50 IOCs ──────────────────────────────
            elapsed = (_utcnow() - start).total_seconds()
            pct = round(done / to_process * 100, 1) if to_process else 0
            rate = round(done / elapsed, 1) if elapsed > 0 else 0
            logger.info(
                "backfill_batch_done",
                batch=batch_num,
                done=done,
                to_process=to_process,
                percent=f"{pct}%",
                success=success,
                skipped=skipped,
                failed=failed,
                elapsed_sec=round(elapsed, 1),
                rate_per_sec=rate,
            )

            if force:
                offset += len(rows)

    finally:
        elapsed = (_utcnow() - start).total_seconds()
        _backfill_stats["current_ioc"] = None
        logger.info(
            "backfill_complete",
            done=done,
            to_process=to_process,
            success=success,
            skipped=skipped,
            failed=failed,
            elapsed_sec=round(elapsed, 1),
            avg_rate_per_sec=round(done / elapsed, 2) if elapsed > 0 else 0,
        )
        _backfill_running = False


# ── Per-IOC endpoints (wildcard /{ioc_id} — must come AFTER literal routes) ──

@router.get("/{ioc_id}", response_model=list[EnrichmentResponse])
async def get_enrichments(ioc_id: str, db: AsyncSession = Depends(get_db)):
    """Get all enrichment data for an IOC."""
    result = await db.execute(
        select(Enrichment).where(Enrichment.ioc_id == ioc_id)
    )
    enrichments = result.scalars().all()
    return [EnrichmentResponse.model_validate(e) for e in enrichments]


@router.post("/{ioc_id}/enrich")
async def trigger_enrichment(
    ioc_id: str,
    request: EnrichmentRequest = EnrichmentRequest(),
    db: AsyncSession = Depends(get_db),
):
    """Trigger enrichment for a single IOC with specified sources."""
    result = await db.execute(select(IOC).where(IOC.id == ioc_id))
    ioc = result.scalar_one_or_none()
    if not ioc:
        raise HTTPException(status_code=404, detail="IOC not found")

    results = await enrich_ioc(db, ioc, sources=request.sources)
    return {"status": "complete", "enrichments": results}
