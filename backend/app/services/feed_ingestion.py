"""Feed ingestion service for fetching, parsing, and storing IOCs from feeds.

Async only. A synchronous mirror of this whole path (``ingest_iocs_sync``,
``_ingest_chunk_sync`` and three ``*_sync`` read helpers) existed for the Celery
tasks and was deleted on 2026-07-31. It was unreachable in production —
``celery_app.beat_schedule`` is entirely commented out and neither ``render.yaml``
nor ``vercel.json`` starts a worker or beat — and maintaining two near-identical
copies of the most intricate code in the repository was actively harmful: they
drifted twice inside a single change set, both times in the sync half, both times
invisible to ``compileall`` because the defects were unbound names on paths no test
exercised.

The live path is ``POST /api/v1/feeds/sync-all`` ->
``feed_scheduler.run_feed_sync`` -> :func:`ingest_iocs`.

If a synchronous caller is ever needed again, wrap the async path with
``asyncio.run`` rather than reintroducing a parallel implementation.
"""

import asyncio
import time
import uuid
from datetime import datetime, timezone
from typing import List, Dict, Any, Optional, Tuple

from sqlalchemy import distinct, func, insert as sa_insert, select, tuple_, update as sa_update
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.ioc import IOC
from app.models.feed import FeedSource
from app.feeds.base import FULL_LIST_CUMULATIVE, FULL_LIST_CURRENT_STATE
from app.models.enrichment import Enrichment
from app.models.ioc_source import IOCSource
from app.services.scoring_engine import calculate_threat_score
from app.utils.db_retry import is_retryable_lock_error
from app.utils.ioc_validator import validate_ioc, normalize_ioc

import structlog

logger = structlog.get_logger()

# Default chunk size for bulk IOC processing. Smaller batches mean fewer rows
# touched per transaction, which reduces InnoDB lock contention. High-volume
# feeds like ThreatFox (~57k IOCs) can override this with a larger batch_size.
_DEFAULT_BATCH_SIZE = 30

# High-volume feeds require larger batches to complete within timeout limits
_HIGH_VOLUME_BATCH_SIZE = 500


def _now() -> datetime:
    """Current UTC time, naive and whole-second — the shape MySQL DATETIME holds.

    Microseconds are dropped deliberately. Every datetime this module produces lands
    in a ``DATETIME`` column with no fractional-seconds precision, and MySQL *rounds*
    what it is given: ``:43.837451`` is stored as ``:44``. So a value written with
    microseconds is not the value that comes back, and any later comparison against
    it is comparing two different normalisations.

    That was a real defect, not a theoretical one. The re-read gate compares a
    source timestamp against the stored ``last_seen``; with rounding on one side and
    not the other, whether the gate fired depended on the microsecond fraction —
    roughly 50/50, with no error either way. Truncating here means MySQL never
    rounds, so stored == written == compared.

    Truncation rather than rounding is chosen so the normalisation is monotonic:
    a truncated value is never *later* than the instant it represents, which keeps
    "has the source advanced" from ever answering yes spuriously.
    """
    return datetime.now(timezone.utc).replace(tzinfo=None, microsecond=0)


def _strip_tz(dt: Optional[datetime]) -> Optional[datetime]:
    """Naive, whole-second datetime for a MySQL ``DATETIME`` column.

    Two normalisations, both required, and the second is easy to overlook:

    * **Timezone** — MySQL rejects an aware value, and the project convention is
      naive UTC throughout (see CLAUDE.md).
    * **Microseconds** — ``DATETIME`` with no fractional-seconds precision rounds
      what it is given, so writing ``:43.837451`` stores ``:44``. Dropping the
      fraction here is what makes the stored value equal the written one, and
      therefore comparable against it later. See :func:`_now` for the defect this
      prevents.

    Applied on **every** write path (the new-row INSERT) and on the comparison side
    (:func:`_source_observed_at`), so the two cannot disagree.
    """
    if dt is None:
        return None
    if getattr(dt, "tzinfo", None) is not None:
        dt = dt.replace(tzinfo=None)
    return dt.replace(microsecond=0)


def _normalize_batch(raw_iocs: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """Validate, normalize, and deduplicate a list of raw IOC dicts."""
    out = []
    seen_keys: set = set()
    for raw in raw_iocs:
        ioc_type = raw.get("type", "")
        value = (raw.get("value") or "").strip()
        if not value or not ioc_type:
            continue
        if not validate_ioc(ioc_type, value):
            continue
        normalized = dict(raw)
        normalized["value"] = normalize_ioc(value, ioc_type)
        key = (ioc_type, normalized["value"])
        if key in seen_keys:
            continue  # deduplicate within-feed duplicate values
        seen_keys.add(key)
        out.append(normalized)
    dropped = len(raw_iocs) - len(out)
    if dropped > 0:
        logger.warning("ioc_validation_dropped", dropped=dropped, total=len(raw_iocs))
    return out


async def ingest_iocs(
    session: AsyncSession,
    feed: FeedSource,
    raw_iocs: List[Dict[str, Any]],
    batch_size: Optional[int] = None,
) -> int:
    """Ingest a batch of IOCs from a feed using bulk operations.

    Processes IOCs in small chunks (batch_size rows) and commits after each
    chunk to release InnoDB row locks promptly. Each chunk is wrapped in retry
    logic: on ER_LOCK_WAIT_TIMEOUT (1205) or ER_LOCK_DEADLOCK (1213) the
    chunk transaction is rolled back and retried with exponential back-off
    (1 s → 2 s → 4 s) via _process_async_chunk_with_retry.
    Returns the total number of IOCs processed.
    
    Args:
        session: Database session
        feed: FeedSource model
        raw_iocs: List of raw IOC dictionaries
        batch_size: Number of IOCs per commit (defaults to 15, use 500 for high-volume feeds)
    """
    if batch_size is None:
        batch_size = _DEFAULT_BATCH_SIZE
    
    valid = _normalize_batch(raw_iocs)
    total_batches = (len(valid) + batch_size - 1) // batch_size  # ceiling division
    logger.info("feed_ingest_start", feed=feed.name, valid=len(valid), total=len(raw_iocs), batch_size=batch_size, total_batches=total_batches)

    feed_id = feed.id
    feed_name = feed.name
    count = 0
    batch_num = 0

    for chunk_start in range(0, len(valid), batch_size):
        batch_num += 1
        chunk = valid[chunk_start : chunk_start + batch_size]
        chunk_count = await _process_async_chunk_with_retry(session, feed_id, chunk)
        count += chunk_count
        
        # Log progress every 10 batches to track ingestion progress
        if batch_num % 10 == 0 or batch_num == total_batches:
            logger.info("feed_ingest_progress", feed=feed_name, batch=batch_num, total_batches=total_batches, processed=count)

    # Re-fetch feed after the last chunk commit for the final status update.
    result = await session.execute(
        select(FeedSource).where(FeedSource.id == feed_id)
    )
    feed = result.scalar_one_or_none()
    if feed:
        feed.last_sync_at = _now()
        if count == 0:
            feed.last_sync_status = "no_data"
            logger.warning("feed_ingestion_no_data", feed=feed_name, raw_total=len(raw_iocs))
        else:
            feed.last_sync_status = "success"
        feed.ioc_count = count
        await session.flush()

    logger.info("feed_ingestion_complete", feed=feed_name, iocs_ingested=count)
    return count


async def _distinct_feed_counts_async(
    session: AsyncSession, ioc_ids: List[str]
) -> Dict[str, int]:
    """Map ioc_id -> number of distinct feeds already reporting it.

    One grouped query for the whole chunk. Drives the source-diversity term,
    which must reflect independent corroboration rather than sighting volume.
    """
    if not ioc_ids:
        return {}
    result = await session.execute(
        select(IOCSource.ioc_id, func.count(distinct(IOCSource.feed_id)))
        .where(IOCSource.ioc_id.in_(ioc_ids))
        .group_by(IOCSource.ioc_id)
    )
    return {row[0]: int(row[1] or 0) for row in result}


async def _already_linked_async(
    session: AsyncSession, feed_id: str, ioc_ids: List[str]
) -> set:
    """IOC ids already linked to this feed, so re-syncs don't double-count it."""
    if not ioc_ids:
        return set()
    result = await session.execute(
        select(IOCSource.ioc_id).where(
            IOCSource.feed_id == feed_id,
            IOCSource.ioc_id.in_(ioc_ids),
        )
    )
    return {row[0] for row in result}


def _decode_json_column(value: Any, fallback: Any) -> Any:
    """MySQL JSON arrives parsed or as a raw string depending on driver/version.

    Malformed content degrades to *fallback* rather than raising: this runs inside
    the ingest loop, and one bad enrichment payload must not abort the chunk.
    """
    if value is None:
        return fallback
    if isinstance(value, (dict, list)):
        return value
    if isinstance(value, (bytes, bytearray)):
        value = value.decode("utf-8", "replace")
    if isinstance(value, str):
        import json

        try:
            return json.loads(value)
        except (ValueError, TypeError):
            return fallback
    return fallback


def _rescore_reason(
    existing: IOC,
    raw: Dict[str, Any],
    merged_tags: List[str],
    merged_tech: List[str],
    is_new_source_link: bool,
) -> Optional[str]:
    """Why this existing row needs re-scoring, or ``None`` to skip it entirely.

    THE PROBLEM THIS SOLVES. Every re-read used to recompute and rewrite
    ``threat_score`` unconditionally. For URLhaus that is 15,524 rows four times a
    day against a shared MySQL host — the InnoDB contention scenario the chunking
    exists for — and almost all of it rewrote values that had not changed. It also
    inflated ``sighting_count`` by one per read (~122 times over a URLhaus URL's
    30.5-day window) and overwrote ``last_seen`` with ingest time, which between
    them decoupled 30% of the default composite from the indicator.

    WHY IT IS NOT JUST A TIMESTAMP CHECK. A pure timestamp gate would throw away the
    two changes that motivated passing enrichment in at all:

    * **A new feed starts reporting an existing IOC.** ``source_count`` goes 1 -> 2,
      so the diversity term goes 30.0 -> 60.0 — 20% of the composite — while
      ``last_seen`` does not move. Skipping that row would leave a stale
      single-source score until something unrelated happened to change it.
    * **Tags or ATT&CK techniques change.** Both feed the context term, and a feed
      re-classifying an indicator is real new information.

    So the gate is a disjunction, and the middle term costs nothing: it is exactly
    what the ``_already_linked`` query already returns.

    Returns a short reason string rather than a bool, because "why was this row
    rewritten" is the question anyone investigating write volume will ask.
    """
    list_kind = raw.get("_full_list_kind")

    if list_kind == FULL_LIST_CURRENT_STATE:
        # `last_seen` advances every sync for these (presence re-asserts liveness),
        # so the row genuinely changes and must be re-scored. The write saving below
        # therefore does not extend to them — a deliberate trade, since recency
        # accuracy is the only signal these feeds carry, and it is unchanged from
        # before the gate. What did change is that their counter stopped inflating.
        return "full-list-current-state"

    # Checks that apply to every feed, timestamped or not. These come first so the
    # kind-specific tails below cannot short-circuit them: a new feed link or a
    # re-classification is new evidence regardless of what kind of list it came from.
    if is_new_source_link:
        return "new-source-link"
    if set(merged_tags) != set(existing.tags or []):
        return "tags-changed"
    if set(merged_tech) != set(existing.mitre_techniques or []):
        return "techniques-changed"

    if list_kind == FULL_LIST_CUMULATIVE:
        # The list only grows and carries no timestamps, so once the shared checks
        # above pass there is nothing left that could have changed. Skip entirely —
        # which makes CISA KEV, eCrimeLabs and MISP CERT-FR (~7,128 records per sync)
        # free to re-read as well as correctly scored.
        #
        # This must be tested BEFORE the `_source_timestamped` fallback: these feeds
        # supply no timestamps, so that fallback would otherwise catch them and
        # rescore every row on every sync — which it did until this was reordered.
        return None

    # A feed with no source timestamps and no full-list declaration keeps its
    # previous always-rescore behaviour. `_make_ioc` defaults an absent
    # first_seen/last_seen to now(), so for those feeds every sync is
    # indistinguishable from a genuine fresh observation and there is nothing to
    # gate on. See BaseFeed._make_ioc's `_source_timestamped`.
    if not raw.get("_source_timestamped"):
        return "no-source-timestamp"

    source_seen = _source_observed_at(raw)
    if source_seen is not None:
        stored = existing.last_seen
        if stored is None or source_seen > stored:
            return "timestamp-advanced"

    return None


def _next_sighting_and_last_seen(
    existing: IOC, raw: Dict[str, Any]
) -> Tuple[int, Optional[datetime], bool]:
    """``(sighting_count, last_seen, advanced)`` for a row being re-scored.

    Two regimes, and conflating them was a real bug caught by test:

    **Source reports timestamps** (URLhaus, ThreatFox, MalwareBazaar, CISA KEV).
    Advance the counter and ``last_seen`` only when the source's own observation
    time moves past what is stored. Incrementing per read counted how many times a
    file had been downloaded — ~122 times over a URLhaus URL's 30.5-day window —
    rather than how often the indicator was observed.

    **Source reports nothing** (blocklist.de, Emerging Threats). ``_make_ioc``
    defaults both stamps to ``now()``, so there is no source time to compare and
    every sync is indistinguishable from a genuine fresh observation. These keep
    their previous behaviour exactly: increment, and stamp ``last_seen`` with ingest
    time. An earlier version of this gate froze them at one sighting forever, which
    is worse than the inflation it was fixing.
    """
    list_kind = raw.get("_full_list_kind")

    if list_kind == FULL_LIST_CURRENT_STATE:
        # The list expires entries, so remaining on it is the source re-asserting
        # that the indicator is live — genuine recency information, and the only
        # signal these feeds carry. Advance `last_seen`; the counter stays put,
        # because presence is not an observation *event*.
        return (existing.sighting_count or 0), _now(), True

    if list_kind == FULL_LIST_CUMULATIVE:
        # The list only grows, so presence today says nothing about today. Freeze
        # both. Advancing `last_seen` here would pin `_recency_score` at 100.0
        # forever and destroy the decay the CVE weight profile depends on — every
        # KEV CVE would hold its day-0 score permanently. It would also count KEV
        # membership a third time, alongside `nvd_in_kev` and the `cisa-kev` tag.
        return (existing.sighting_count or 0), (existing.last_seen or _now()), False

    if not raw.get("_source_timestamped"):
        # No timestamps and not declared a full list: keep the previous behaviour
        # rather than guessing. Freezing a counter for a feed that might genuinely
        # be reporting new observations would be the same class of error in the
        # other direction.
        return (existing.sighting_count or 0) + 1, _now(), True

    source_seen = _source_observed_at(raw)
    advanced = source_seen is not None and (
        existing.last_seen is None or source_seen > existing.last_seen
    )
    if advanced:
        return (existing.sighting_count or 0) + 1, source_seen, True
    return (existing.sighting_count or 0), (existing.last_seen or _now()), False


def _source_observed_at(raw: Dict[str, Any]) -> Optional[datetime]:
    """The source's own observation time for this IOC, naive UTC, or None.

    Prefers ``last_seen`` (URLhaus's ``last_online``, which genuinely advances when
    a URL is re-confirmed) and falls back to ``first_seen`` (``dateadded``,
    ``first_seen_utc`` — which never advance, so those feeds settle at one sighting).

    Whole-second, via :func:`_strip_tz` — which is also what the write path uses, so
    the compared and stored values are normalised identically. See :func:`_now` for
    why that matters: with rounding on one side only, the re-read gate fired or did
    not fire depending on the microsecond fraction.
    """
    return _strip_tz(raw.get("last_seen")) or _strip_tz(raw.get("first_seen"))


async def _enrichments_for_async(
    session: AsyncSession, ioc_ids: List[str]
) -> Dict[str, List[Dict[str, Any]]]:
    """Existing enrichment rows for these IOCs, in scoring-engine shape.

    WHY THIS EXISTS. The re-read path recomputes ``threat_score``, and until
    2026-07-30 it did so **without** passing ``enrichment_data``. That made
    ``_enrichment_risk_score`` fall to its 20.0 floor and — because
    ``_base_reputation_score`` resolves both the reputation payload *and*, for
    CVEs, the NVD CVSS score out of the same list — collapsed the reputation term
    to ``NEUTRAL_REPUTATION`` too. Measured cost of one re-read on a fully
    enriched indicator: -23 for an IP or URL, **-44 for a KEV CVE**, which moved
    it from critical to medium. Every sync overwrote the enrichment-informed
    score with a non-enriched one.

    Fetched as ONE grouped query per chunk, matching the bulk-read shape of the
    rest of this function and the four-statements-per-chunk budget in
    ``scripts/rescore_corpus.py``. A per-row fetch here would be an N+1 across the
    public internet to a shared host — the pattern this module exists to avoid.
    """
    if not ioc_ids:
        return {}
    result = await session.execute(
        select(Enrichment.ioc_id, Enrichment.source, Enrichment.data).where(
            Enrichment.ioc_id.in_(ioc_ids)
        )
    )
    grouped: Dict[str, List[Dict[str, Any]]] = {}
    for ioc_id, source, data in result:
        grouped.setdefault(ioc_id, []).append(
            {"source": source, "data": _decode_json_column(data, {})}
        )
    return grouped


async def _ingest_chunk(
    session: AsyncSession,
    feed: FeedSource,
    chunk: List[Dict[str, Any]],
) -> int:
    """Process one chunk: bulk-lookup existing IOCs, update or insert, link sources.

    Existing-row mutations are accumulated as plain dicts and applied via a
    single ``session.execute(sa_update(IOC), ...)`` executemany call.
    This holds InnoDB row locks only for the duration of that one statement
    instead of spreading them across the Python-side computation loop, which
    is the primary cause of ER_LOCK_WAIT_TIMEOUT (1205) under concurrent
    workers. New INSERTs still use individual savepoints to handle the
    UNIQUE(type, value) race with other concurrent workers gracefully.
    """
    # Build (type, value) lookup key for all IOCs in this chunk.
    keys: List[Tuple[str, str]] = [(r["type"], r["value"]) for r in chunk]

    # Single SELECT — read phase is lock-free (no FOR UPDATE here).
    existing_rows = await session.execute(
        select(IOC).where(tuple_(IOC.type, IOC.value).in_(keys))
    )
    existing_map: Dict[Tuple[str, str], IOC] = {
        (ioc.type, ioc.value): ioc for ioc in existing_rows.scalars()
    }

    # How many DISTINCT feeds already report each existing IOC. Fetched as one
    # grouped query before the loop, matching the bulk-read/bulk-write shape of
    # the rest of this function — per-row queries here would reintroduce the
    # lock-hold-during-Python-work problem the chunking is designed to avoid.
    existing_ids = [ioc.id for ioc in existing_map.values()]
    feed_counts = await _distinct_feed_counts_async(session, existing_ids)
    linked_to_this_feed = await _already_linked_async(session, feed.id, existing_ids)
    # Enrichment evidence for the re-scoring below. Without it every re-read
    # overwrote an enrichment-informed score with a non-enriched one — see
    # _enrichments_for_async.
    # Enrichment is fetched AFTER the gate below, for only the rows that will
    # actually be re-scored. Fetching it here — before knowing which rows changed —
    # costs a round-trip per chunk even when the gate skips every row, which for
    # URLhaus steady state is almost all of them. Ordering, not detail.

    count = 0
    ioc_ids: List[str] = []
    # Collect field values for existing-row updates WITHOUT mutating tracked ORM objects.
    # Using a plain dict + executemany UPDATE sends one round-trip and releases locks immediately.
    update_mappings: List[Dict[str, Any]] = []
    # Collect new IOC rows for a single bulk INSERT IGNORE — no per-IOC savepoints.
    new_ioc_rows: List[Dict[str, Any]] = []
    new_ioc_ids: List[str] = []

    # ── Pass 1: which existing rows actually need re-scoring? ────────────────
    # Queries nothing — the gate reads only data already in hand.
    skipped_unchanged = 0
    rescore_plan: Dict[Tuple[str, str], Tuple[List[str], List[str], int, str]] = {}
    for raw in chunk:
        existing = existing_map.get((raw["type"], raw["value"]))
        if not existing:
            continue
        merged_tags = list(set(existing.tags or []) | set(raw.get("tags") or []))
        merged_tech = list(
            set(existing.mitre_techniques or []) | set(raw.get("mitre_techniques") or [])
        )
        is_new_link = existing.id not in linked_to_this_feed
        source_count = feed_counts.get(existing.id, 0) + (1 if is_new_link else 0)
        reason = _rescore_reason(existing, raw, merged_tags, merged_tech, is_new_link)
        if reason is None:
            skipped_unchanged += 1
            continue
        rescore_plan[(raw["type"], raw["value"])] = (
            merged_tags, merged_tech, source_count, reason
        )

    # ── Enrichment for the gated subset only ─────────────────────────────────
    enrichment_map = await _enrichments_for_async(
        session,
        [existing_map[k].id for k in rescore_plan if k in existing_map],
    )

    for raw in chunk:
        key = (raw["type"], raw["value"])
        existing = existing_map.get(key)

        try:
            if existing:
                if key not in rescore_plan:
                    # Unchanged: no UPDATE, no sighting increment, no last_seen
                    # rewrite. Still counted as processed, and its ioc_sources link
                    # is still ensured by the write phase below.
                    ioc_ids.append(existing.id)
                    count += 1
                    continue

                merged_tags, merged_tech, source_count, _reason = rescore_plan[key]

                # Counter and last_seen both come from the source's own observation
                # time where one exists — see _next_sighting_and_last_seen.
                new_sighting, new_last_seen, _advanced = (
                    _next_sighting_and_last_seen(existing, raw)
                )

                new_score = calculate_threat_score(
                    {
                        "type": existing.type,
                        "value": existing.value,
                        "tags": merged_tags,
                        "mitre_techniques": merged_tech,
                        "last_seen": new_last_seen,
                        "sighting_count": new_sighting,
                        "metadata": existing.metadata_,
                    },
                    source_count=max(source_count, 1),
                    # Existing enrichment must be passed in, or both the
                    # enrichment-risk term and the reputation term (which reads
                    # the reputation payload and, for CVEs, the NVD CVSS score out
                    # of this same list) collapse to their no-evidence defaults.
                    enrichment_data=enrichment_map.get(existing.id, []),
                    # This row is being written because an enabled feed reported
                    # it, so the 0.0 reputation floor never applies here.
                    has_enabled_feed_source=True,
                )
                update_mappings.append({
                    "id": existing.id,
                    "sighting_count": new_sighting,
                    "last_seen": new_last_seen,
                    "tags": merged_tags,
                    "mitre_techniques": merged_tech,
                    "threat_score": new_score,
                    "updated_at": _now(),
                })
                ioc_ids.append(existing.id)
            else:
                new_id = str(uuid.uuid4())
                score = raw.get("threat_score") or calculate_threat_score(
                    raw, source_count=1, has_enabled_feed_source=True
                )
                now = _now()
                new_ioc_rows.append({
                    "id": new_id,
                    "type": raw["type"],
                    "value": raw["value"],
                    "threat_score": score,
                    "confidence": raw.get("confidence", 50),
                    "first_seen": _strip_tz(raw.get("first_seen")) or now,
                    "last_seen": _strip_tz(raw.get("last_seen")) or now,
                    "sighting_count": 1,
                    "tags": raw.get("tags", []),
                    "metadata": raw.get("metadata", {}),
                    "mitre_techniques": raw.get("mitre_techniques", []),
                    "created_at": now,
                    "updated_at": now,
                })
                new_ioc_ids.append(new_id)

            count += 1
        except Exception as e:
            logger.error("ioc_chunk_error", error=str(e), value=raw.get("value", "")[:50])

    if skipped_unchanged:
        logger.info(
            "ingest_chunk_skipped_unchanged",
            feed=feed.slug,
            skipped=skipped_unchanged,
            rescored=len(rescore_plan),
            existing_rows=len(existing_map),
        )
    # Single INSERT IGNORE for all new IOCs — one DB round-trip, no per-IOC savepoints.
    # INSERT IGNORE silently skips rows that violate UNIQUE(type, value) (concurrent-insert
    # race with another worker) without raising an exception.
    if new_ioc_rows:
        await session.execute(
            sa_insert(IOC.__table__).prefix_with("IGNORE").values(new_ioc_rows)
        )
        ioc_ids.extend(new_ioc_ids)

    # Single executemany UPDATE — one DB round-trip, minimal lock window.
    if update_mappings:
        await session.execute(sa_update(IOC), update_mappings)

    await session.flush()

    # Bulk-check which (ioc_id, feed_id) source links already exist, then INSERT IGNORE
    # all new links in one statement. INSERT IGNORE handles FK misses for any IOC whose
    # INSERT was silently skipped above (concurrent-insert race, extremely rare).
    if ioc_ids:
        existing_sources = await session.execute(
            select(IOCSource.ioc_id).where(
                IOCSource.feed_id == feed.id,
                IOCSource.ioc_id.in_(ioc_ids),
            )
        )
        already_linked = {row[0] for row in existing_sources}

        seen: set = set()
        new_source_rows: List[Dict[str, Any]] = []
        for ioc_id in ioc_ids:
            if ioc_id not in already_linked and ioc_id not in seen:
                new_source_rows.append({
                    "id": str(uuid.uuid4()),
                    "ioc_id": ioc_id,
                    "feed_id": feed.id,
                    "ingested_at": _now(),
                })
                seen.add(ioc_id)

        if new_source_rows:
            await session.execute(
                sa_insert(IOCSource.__table__).prefix_with("IGNORE").values(new_source_rows)
            )

        await session.flush()

    return count


async def _process_async_chunk_with_retry(
    session: AsyncSession,
    feed_id: str,
    chunk: List[Dict[str, Any]],
    max_retries: int = 3,
    base_delay: float = 1.0,
) -> int:
    """Process one async chunk and commit; retry on InnoDB lock contention.

    On ER_LOCK_WAIT_TIMEOUT (1205) or ER_LOCK_DEADLOCK (1213) the entire
    chunk transaction is rolled back and re-executed after exponential
    back-off: 1 s, 2 s, 4 s. Rolling back before the next attempt resets
    the session to a clean state with no stale row locks.

    The feed row is re-fetched at the start of every attempt because
    ``rollback()`` expires all session-bound ORM objects — accessing an
    expired object's attributes raises DetachedInstanceError.
    """
    last_exc: Optional[Exception] = None
    for attempt in range(max_retries + 1):
        try:
            # Always re-fetch the feed; after a rollback the previously
            # loaded instance is expired and unusable.
            result = await session.execute(
                select(FeedSource).where(FeedSource.id == feed_id)
            )
            feed = result.scalar_one_or_none()
            if not feed:
                return 0

            count = await _ingest_chunk(session, feed, chunk)
            # Commit immediately — this releases all InnoDB row locks and is
            # the primary defence against ER_LOCK_WAIT_TIMEOUT (1205) when
            # multiple workers update overlapping IOC sets concurrently.
            await session.commit()
            return count
        except Exception as exc:
            # Always roll back on any error so the next attempt (or the
            # caller) starts from a clean transaction state.
            await session.rollback()
            if not is_retryable_lock_error(exc) or attempt == max_retries:
                raise
            last_exc = exc
            delay = base_delay * (2 ** attempt)
            logger.warning(
                "async_chunk_lock_retry",
                attempt=attempt + 1,
                max_retries=max_retries,
                delay_s=delay,
                error=str(exc),
            )
            await asyncio.sleep(delay)
    raise last_exc  # type: ignore[misc]  — unreachable, satisfies type-checkers


