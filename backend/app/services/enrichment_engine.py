"""Multi-source enrichment orchestrator for IOCs."""

import asyncio
from datetime import datetime, timezone, timedelta
from typing import Dict, Any, List, Optional, Tuple

from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select
from sqlalchemy.exc import IntegrityError

from app.models.ioc import IOC
from app.models.enrichment import Enrichment
from app.services.scoring_engine import calculate_threat_score

import structlog

logger = structlog.get_logger()


def _utcnow() -> datetime:
    """Return current UTC time as a timezone-naive datetime for MySQL DateTime columns."""
    return datetime.now(timezone.utc).replace(tzinfo=None)


# Ceiling on enrichers running at once, process-wide (Phase 5).
#
# `asyncio.gather` over the applicable sources was unbounded. Per IOC that is at most
# five or six calls, which is fine — but the bulk backfill enriches up to 50,000 IOCs and
# `POST /feeds/sync-all` drives enrichment behind a single request, so the in-flight total
# is (IOCs being processed × sources each), with nothing capping it.
#
# Three costs, all on a Render free instance limited to `cpus: 0.1` and 512 MB:
#
#   * every enricher opens its own `httpx.AsyncClient` with a 15 s timeout, so sockets and
#     TLS buffers scale with the fan-out;
#   * WHOIS is blocking and runs via `run_in_executor`, so unbounded fan-out queues work
#     onto the default thread pool, whose size is a function of CPU count — a tenth of a
#     core does not absorb that;
#   * third-party rate limits are per API key, not per task. NVD without a key allows five
#     requests per 30 s, so parallelism beyond a handful converts directly into 429s and
#     retries, which is slower than doing less at once.
#
# A semaphore rather than a smaller batch size because the sources have very different
# latencies (a DNS lookup against a WHOIS query): a semaphore keeps the fast ones cycling
# while a slow one holds its slot, where fixed batches would idle behind the slowest
# member of each batch. Module-level so the bound is process-wide rather than per call —
# a per-call semaphore would cap fan-out within one IOC and not across a backfill, which
# is the case that actually needs it.
ENRICHMENT_CONCURRENCY = 5
_enrichment_semaphore = asyncio.Semaphore(ENRICHMENT_CONCURRENCY)


async def _run_enricher_bounded(source: str, ioc: IOC) -> Optional[Dict[str, Any]]:
    """`_run_enricher` behind the concurrency ceiling.

    Kept as a thin wrapper so `_run_enricher` stays directly callable and independently
    testable, and so the bound is visible at the call site rather than hidden inside the
    enricher dispatch.
    """
    async with _enrichment_semaphore:
        return await _run_enricher(source, ioc)


async def enrich_ioc(
    session: AsyncSession,
    ioc: IOC,
    sources: Optional[List[str]] = None,
) -> List[Dict[str, Any]]:
    """Run enrichment pipeline for an IOC.

    Runs applicable enrichers in parallel and stores each result as a
    separate row in the enrichments table (one row per source per IOC).
    """
    if sources is None:
        sources = _get_applicable_sources(ioc.type)

    results: List[Dict[str, Any]] = []

    # Pass 1: collect cached results; build list of sources that still need enriching.
    pending_sources: List[str] = []
    for source in sources:
        cached = await _get_cached_enrichment(session, ioc.id, source)
        if cached:
            results.append(cached)
        else:
            pending_sources.append(source)

    if not pending_sources:
        return results

    # Pass 2: run all pending enrichers in parallel, but bounded.
    enrichment_results = await asyncio.gather(
        *[_run_enricher_bounded(s, ioc) for s in pending_sources],
        return_exceptions=True,
    )

    for source, result in zip(pending_sources, enrichment_results):
        if isinstance(result, Exception):
            logger.error("enrichment_failed", source=source, ioc=ioc.value, error=str(result))
            continue

        if not result:
            continue

        now = _utcnow()
        expires = now + timedelta(seconds=_get_ttl(source))

        existing_row = await session.execute(
            select(Enrichment).where(
                Enrichment.ioc_id == ioc.id,
                Enrichment.source == source,
            )
        )
        existing_record = existing_row.scalar_one_or_none()

        if existing_record:
            existing_record.data = result
            existing_record.enriched_at = now
            existing_record.expires_at = expires
        else:
            session.add(Enrichment(
                ioc_id=ioc.id,
                source=source,
                data=result,
                enriched_at=now,
                expires_at=expires,
            ))

        results.append({"source": source, "data": result})

    # Flush enrichment changes using a nested transaction (savepoint)
    # This allows us to rollback just the enrichment on error without
    # poisoning the outer transaction managed by FastAPI's get_db() dependency
    async with session.begin_nested():
        try:
            await session.flush()
        except IntegrityError as e:
            # Duplicate enrichment - another request beat us to it (race condition)
            # The savepoint automatically rolls back, session remains clean
            logger.info("enrichment_duplicate_ignored", 
                        ioc_id=ioc.id, 
                        error=str(e))
            # Re-query cached enrichments after savepoint rollback
            cached_results = []
            for source in sources:
                cached = await _get_cached_enrichment(session, ioc.id, source)
                if cached:
                    cached_results.append(cached)
            source_count, has_enabled_source = await _feed_source_evidence(session, ioc.id)
            _rescore_from_enrichment(
                ioc, cached_results, source_count, has_enabled_source
            )
            return cached_results

    source_count, has_enabled_source = await _feed_source_evidence(session, ioc.id)
    _rescore_from_enrichment(ioc, results, source_count, has_enabled_source)
    return results


async def _feed_source_evidence(session: AsyncSession, ioc_id) -> Tuple[int, Optional[bool]]:
    """Both feed-derived scoring inputs, from one statement.

    Returns ``(distinct_feed_count, has_enabled_feed_source)``:

    * the count drives source diversity and is deliberately **not**
      ``sighting_count`` — a single feed re-publishing its catalogue must not read
      as independent corroboration.
    * the flag gates the 0.0 reputation floor. It is a separate value rather than
      a filter on the count because filtering the count on
      ``feed_sources.is_enabled`` would move the diversity term for every
      indicator a since-disabled feed once reported.

    On failure the flag is ``None`` — "unknown" — which the scoring engine treats
    as "assume a feed source exists", so a failed query can never make an
    indicator look clean.
    """
    from sqlalchemy import distinct, func

    from app.models.feed import FeedSource
    from app.models.ioc_source import IOCSource

    try:
        result = await session.execute(
            select(
                func.count(distinct(IOCSource.feed_id)),
                func.max(func.coalesce(FeedSource.is_enabled, False)),
            )
            .select_from(IOCSource)
            .outerjoin(FeedSource, FeedSource.id == IOCSource.feed_id)
            .where(IOCSource.ioc_id == ioc_id)
        )
        row = result.one_or_none()
        if row is None:
            return 0, False
        return int(row[0] or 0), bool(row[1])
    except Exception as exc:
        logger.warning("feed_source_evidence_failed", ioc_id=str(ioc_id), error=str(exc))
        return 0, None


def _rescore_from_enrichment(
    ioc: IOC,
    results: List[Dict[str, Any]],
    source_count: int = 1,
    has_enabled_feed_source: Optional[bool] = None,
) -> None:
    """Recompute the IOC's threat score now that enrichment data is available.

    Enrichment feeds two terms: the risk signals (GeoIP country, domain age,
    fast flux, CVSS, CISA KEV membership, public exploit availability, YARA
    matches) and — via ``_base_reputation_score`` — the reputation term itself.
    Ingestion scores an IOC before any enrichment exists, so without this step
    both are evaluated against an empty list and the evidence is discarded.

    Mutation only; the caller's transaction persists it.
    """
    if not results:
        return

    try:
        new_score = calculate_threat_score(
            {
                "type": ioc.type,
                "value": ioc.value,
                "tags": ioc.tags or [],
                "mitre_techniques": ioc.mitre_techniques or [],
                "last_seen": ioc.last_seen,
                "sighting_count": ioc.sighting_count or 1,
                "metadata": ioc.metadata_,
            },
            source_count=max(source_count, 1),
            enrichment_data=results,
            has_enabled_feed_source=has_enabled_feed_source,
        )
    except Exception as exc:  # scoring must never break an enrichment pass
        logger.warning("rescore_after_enrichment_failed", ioc_id=str(ioc.id), error=str(exc))
        return

    if new_score != ioc.threat_score:
        logger.info(
            "threat_score_updated_from_enrichment",
            ioc_id=str(ioc.id),
            old_score=ioc.threat_score,
            new_score=new_score,
        )
        ioc.threat_score = new_score


def _get_applicable_sources(ioc_type: str) -> List[str]:
    """Determine which enrichment sources apply to an IOC type.

    Delegates entirely to the enricher registry: each enricher's ``supports()``
    decides applicability, and registry order decides the order sources are
    attempted. ``reputation`` supports every type, so an unrecognised IOC type
    still receives it as a fallback.
    """
    from app.enrichers import applicable_sources as _registry_sources

    try:
        return _registry_sources(ioc_type)
    except Exception as exc:  # a broken registry must not block enrichment
        logger.error("enricher_registry_unavailable", error=str(exc))
        return []


async def _get_cached_enrichment(
    session: AsyncSession, ioc_id, source: str
) -> Optional[Dict]:
    """Return a non-expired cached enrichment row, or None."""
    result = await session.execute(
        select(Enrichment).where(
            Enrichment.ioc_id == ioc_id,
            Enrichment.source == source,
        )
    )
    enrichment = result.scalar_one_or_none()

    if enrichment and enrichment.expires_at:
        # expires_at is stored as a naive UTC datetime in MySQL.
        # Compare to _utcnow() (also naive) to avoid TypeError from
        # mixing offset-naive and offset-aware datetimes.
        if enrichment.expires_at > _utcnow():
            return {"source": source, "data": enrichment.data}

    return None


async def _run_enricher(source: str, ioc: IOC) -> Optional[Dict]:
    """Dispatch to a registered enricher; never raises so gather stays clean.

    A registered enricher may return None to signal "not applicable to this
    particular value" — for example YARAify only handles SHA256 — in which case
    no row is stored and nothing is cached.
    """
    from app.enrichers import get_enricher

    enricher = get_enricher(source)
    if enricher is None:
        logger.warning("enricher_not_registered", source=source)
        return None

    try:
        return await enricher.enrich(ioc.value, ioc.type)
    except Exception as e:
        # BaseEnricher forbids raising, but a bug in one source must never take
        # down the whole enrichment pass.
        logger.error("enricher_error", source=source, error=str(e))
        return None


def _get_ttl(source: str) -> int:
    """Cache TTL in seconds for an enrichment source.

    Each enricher declares its own ``cache_ttl``; the config-backed values
    (WHOIS/DNS/GeoIP/reputation) are exposed as properties on those classes.
    """
    from app.enrichers import get_enricher

    enricher = get_enricher(source)
    if enricher is not None:
        return enricher.cache_ttl
    return 3600
