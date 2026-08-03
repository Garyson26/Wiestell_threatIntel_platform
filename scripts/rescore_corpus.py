#!/usr/bin/env python3
"""Recompute every stored ``iocs.threat_score`` against the current scoring model.

WHY THIS EXISTS
---------------
Stored scores are stale corpus-wide, because the scoring *inputs* changed:

1. ``_base_reputation_score`` fed the computed ``threat_score`` back into itself,
   so 30% of each composite was 30% of the previous one.
2. Source diversity was passed the sighting count, so a single feed re-publishing
   its catalogue five times scored as "5+ independent sources" (100.0) instead of
   30.0 for one true source.
3. Provider silence was scored as evidence of cleanliness (reputation 0.0).
4. A failed enricher diluted the enrichment-risk ratio.

The dashboard, the score filters and the ATT&CK heatmap all read stored scores,
so recomputing is not optional. **Expect the distribution to shift down**: (2) in
particular was inflating diversity for most of the corpus. That is a correction,
not a regression — but a tester who has seen the old dashboard will read it as
one, which is why ``--dry-run`` prints the before/after bands.

WHERE TO RUN IT
---------------
From a developer machine, against the Hostinger DSN. **Not on Render**: free
instances have no shell and no one-off jobs, and spin-down would kill a long run.

    cd backend
    DATABASE_URL="mysql+pymysql://user:pass@host/db" \
    SECRET_KEY="$(python -c 'import secrets;print(secrets.token_urlsafe(48))')" \
    python ../scripts/rescore_corpus.py --dry-run

Review the distribution, get sign-off, then drop ``--dry-run``.

DESIGN NOTES
------------
*Transactions.* This script owns its session and commits directly. It deliberately
does **not** follow the API's ``flush()``-only convention — that exists because
``get_db()`` commits when a request handler returns, which does not apply here.

*Chunking.* A bulk ``UPDATE`` across ``iocs`` on a shared MySQL host is exactly
the lock-contention scenario ``services/feed_ingestion.py`` was tuned to survive,
so this reuses that shape rather than reinventing it: ~30 rows per chunk, one
commit per chunk, and retry with exponential back-off on 1205 (lock wait timeout)
and 1213 (deadlock) via ``utils/db_retry``.

*Four statements per chunk, not thirty-one.* Scoring needs the IOC row, its
distinct feed count and its enrichment rows. Fetching those per-IOC would be an
N+1 across the public internet — the pattern the rest of this work removes. Per
chunk:

    1. SELECT the chunk of IOC rows (keyset paginated)
    2. one SELECT ... GROUP BY over ioc_sources -> COUNT(DISTINCT feed_id)
       *and* MAX(is_enabled) over the feed_sources join, in the same statement
    3. one SELECT over enrichments for those ids, grouped in Python
    4. one executemany UPDATE

Statement 2 returns both feed-derived scoring inputs together on purpose. Two
queries would break the budget *and* let the values drift if a feed were toggled
mid-run.

*Resumability.* Keyset pagination on ``id`` (``WHERE id > :last ORDER BY id``).
IDs are ``CHAR(36)`` UUID strings, so ordering is lexicographic but stable.
``--start-after`` resumes an interrupted run. The script is idempotent: scoring is
a pure function of evidence, so re-running from the beginning converges to the
same values.
"""

from __future__ import annotations

import argparse
import os
import sys
from collections import Counter, defaultdict
from typing import Any, Dict, Iterable, List, Optional, Tuple

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "backend"))

from sqlalchemy import bindparam, text  # noqa: E402

from app.database import SyncSessionLocal  # noqa: E402
from app.services.scoring_engine import (  # noqa: E402
    calculate_threat_score,
    get_score_category,
)
from app.utils.db_retry import retry_on_lock_timeout  # noqa: E402

# Matches feed_ingestion's _DEFAULT_BATCH_SIZE. Smaller batches hold row locks
# for less time, which is the whole point on a shared host.
DEFAULT_CHUNK_SIZE = 30

BANDS = ("critical", "high", "medium", "low")


# ── Statement 1 ──────────────────────────────────────────────────────────────

_SELECT_IOCS = """
    SELECT id, type, value, threat_score, tags, metadata, mitre_techniques,
           last_seen, sighting_count
    FROM iocs
    WHERE id > :last_id
    {override_filter}
    ORDER BY id
    LIMIT :limit
"""

# ── Statement 2: both feed-derived inputs, one statement ─────────────────────
#
# COUNT(DISTINCT feed_id) is the source-diversity input and must never be the
# sighting count. MAX(is_enabled) answers "does an enabled feed report this",
# which gates the 0.0 reputation floor. It is deliberately NOT used to filter the
# count: filtering diversity on is_enabled would move the score of every
# indicator that a since-disabled feed once reported.

_SELECT_FEED_EVIDENCE = """
    SELECT s.ioc_id,
           COUNT(DISTINCT s.feed_id) AS feed_count,
           COALESCE(MAX(f.is_enabled), 0) AS has_enabled
    FROM ioc_sources s
    LEFT JOIN feed_sources f ON f.id = s.feed_id
    WHERE s.ioc_id IN :ioc_ids
    GROUP BY s.ioc_id
"""

# ── Statement 3 ──────────────────────────────────────────────────────────────

_SELECT_ENRICHMENTS = """
    SELECT ioc_id, source, data
    FROM enrichments
    WHERE ioc_id IN :ioc_ids
"""

# ── Statement 4 ──────────────────────────────────────────────────────────────

_UPDATE_SCORES = """
    UPDATE iocs SET threat_score = :threat_score WHERE id = :ioc_id
"""


def _json_load(value: Any, fallback: Any) -> Any:
    """MySQL JSON columns arrive as parsed objects or as raw strings.

    Which one depends on driver and server version, so handle both rather than
    assuming. A malformed value degrades to the fallback: this script must not
    abort a 100k-row run over one bad row.
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


def _has_override_column(session) -> bool:
    """Does ``iocs.manual_score_override`` exist yet?

    It ships with a later migration. Probed once so the script is correct both
    before and after: once the column holds analyst-set values this script must
    not overwrite them, because it recomputes unconditionally.
    """
    row = session.execute(
        text(
            "SELECT COUNT(*) FROM information_schema.columns "
            "WHERE table_schema = DATABASE() AND table_name = 'iocs' "
            "AND column_name = 'manual_score_override'"
        )
    ).scalar()
    return bool(row)


class Rescorer:
    """Chunked, resumable, idempotent rescore of the whole ``iocs`` table."""

    def __init__(self, session, chunk_size: int, dry_run: bool, verbose: bool):
        self.session = session
        self.chunk_size = chunk_size
        self.dry_run = dry_run
        self.verbose = verbose
        self.before = Counter()
        self.after = Counter()
        self.changed = 0
        self.scanned = 0
        self.statements = 0
        self.last_id = ""
        self.skipped_overrides = 0
        self._override_filter = ""

    # ── per-chunk statements ────────────────────────────────────────────────

    def _fetch_chunk(self, last_id: str) -> List[Dict[str, Any]]:
        self.statements += 1
        sql = _SELECT_IOCS.format(override_filter=self._override_filter)
        rows = self.session.execute(
            text(sql), {"last_id": last_id, "limit": self.chunk_size}
        ).mappings().all()
        return [dict(r) for r in rows]

    def _fetch_feed_evidence(
        self, ioc_ids: List[str]
    ) -> Dict[str, Tuple[int, bool]]:
        self.statements += 1
        stmt = text(_SELECT_FEED_EVIDENCE).bindparams(
            bindparam("ioc_ids", expanding=True)
        )
        rows = self.session.execute(stmt, {"ioc_ids": ioc_ids}).all()
        return {r[0]: (int(r[1] or 0), bool(r[2])) for r in rows}

    def _fetch_enrichments(self, ioc_ids: List[str]) -> Dict[str, List[Dict]]:
        self.statements += 1
        stmt = text(_SELECT_ENRICHMENTS).bindparams(
            bindparam("ioc_ids", expanding=True)
        )
        rows = self.session.execute(stmt, {"ioc_ids": ioc_ids}).all()
        grouped: Dict[str, List[Dict]] = defaultdict(list)
        for ioc_id, source, data in rows:
            grouped[ioc_id].append({"source": source, "data": _json_load(data, {})})
        return grouped

    def _write_chunk(self, updates: List[Dict[str, Any]]) -> None:
        """One executemany UPDATE, then commit. Retried on lock contention."""

        @retry_on_lock_timeout(max_retries=3, base_delay=1.0)
        def _write():
            try:
                self.session.execute(text(_UPDATE_SCORES), updates)
                self.session.commit()
            except Exception:
                self.session.rollback()
                raise  # the decorator retries 1205 / 1213 and re-raises the rest

        self.statements += 1
        _write()

    # ── scoring ─────────────────────────────────────────────────────────────

    def _score(
        self,
        row: Dict[str, Any],
        feed_evidence: Dict[str, Tuple[int, bool]],
        enrichments: Dict[str, List[Dict]],
    ) -> int:
        ioc_id = row["id"]
        source_count, has_enabled = feed_evidence.get(ioc_id, (0, False))
        return calculate_threat_score(
            {
                "type": row["type"],
                "value": row["value"],
                "tags": _json_load(row["tags"], []),
                "mitre_techniques": _json_load(row["mitre_techniques"], []),
                "last_seen": row["last_seen"],
                "sighting_count": row["sighting_count"] or 1,
                "metadata": _json_load(row["metadata"], {}),
            },
            # Distinct feeds, never the sighting count.
            source_count=max(source_count, 1),
            enrichment_data=enrichments.get(ioc_id, []),
            has_enabled_feed_source=has_enabled,
        )

    # ── driver ──────────────────────────────────────────────────────────────

    def run(self, start_after: str = "") -> None:
        if _has_override_column(self.session):
            # Analyst-set scores win outright and must survive a rescore.
            self._override_filter = "AND manual_score_override IS NULL"
            print("note: manual_score_override exists — rows holding one are skipped")
        else:
            print("note: manual_score_override column absent — no rows skipped")

        self.last_id = start_after
        chunk_index = 0

        while True:
            statements_before = self.statements
            rows = self._fetch_chunk(self.last_id)
            if not rows:
                break

            chunk_index += 1
            ioc_ids = [r["id"] for r in rows]
            feed_evidence = self._fetch_feed_evidence(ioc_ids)
            enrichments = self._fetch_enrichments(ioc_ids)

            updates = []
            for row in rows:
                old = int(row["threat_score"] or 0)
                new = self._score(row, feed_evidence, enrichments)
                self.before[get_score_category(old)] += 1
                self.after[get_score_category(new)] += 1
                self.scanned += 1
                if new != old:
                    self.changed += 1
                    updates.append({"ioc_id": row["id"], "threat_score": new})

            if updates and not self.dry_run:
                self._write_chunk(updates)
            elif self.dry_run:
                # Keep the statement count honest: a real run would issue one more.
                self.statements += 1 if updates else 0

            self.last_id = rows[-1]["id"]

            if self.verbose or chunk_index == 1:
                print(
                    f"chunk {chunk_index}: {len(rows)} rows, {len(updates)} changed, "
                    f"{self.statements - statements_before} statements, "
                    f"last_id={self.last_id}"
                )

            if len(rows) < self.chunk_size:
                break

    # ── reporting ───────────────────────────────────────────────────────────

    def report(self) -> None:
        width = max(10, *(len(b) for b in BANDS))
        print()
        print("=" * 60)
        print("SCORE BAND DISTRIBUTION" + ("  (dry run — nothing written)" if self.dry_run else ""))
        print("=" * 60)
        header = " " * 8 + "".join(f"{b:>{width + 2}}" for b in BANDS)
        print(header)
        print(f"{'before':<8}" + "".join(f"{self.before[b]:>{width + 2}}" for b in BANDS))
        print(f"{'after':<8}" + "".join(f"{self.after[b]:>{width + 2}}" for b in BANDS))
        deltas = [self.after[b] - self.before[b] for b in BANDS]
        print(f"{'delta':<8}" + "".join(f"{d:>+{width + 2}}" for d in deltas))
        print()
        print(f"scanned:          {self.scanned}")
        print(f"score changed:    {self.changed}")
        if self.skipped_overrides:
            print(f"skipped (manual): {self.skipped_overrides}")
        print(f"statements issued: {self.statements}")
        if self.scanned:
            chunks = max(1, (self.scanned + self.chunk_size - 1) // self.chunk_size)
            print(f"statements/chunk:  {self.statements / chunks:.2f} (target: 4)")
        print(f"resume with:      --start-after {self.last_id}")
        if self.dry_run:
            print()
            print("Nothing was written. Re-run without --dry-run to apply.")


def main(argv: Optional[Iterable[str]] = None) -> int:
    parser = argparse.ArgumentParser(
        description="Recompute every iocs.threat_score against the current model.",
        epilog="Run with --dry-run first and get sign-off on the distribution.",
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="compute and report the band distribution without writing",
    )
    parser.add_argument(
        "--chunk-size",
        type=int,
        default=DEFAULT_CHUNK_SIZE,
        help=f"rows per chunk and per commit (default {DEFAULT_CHUNK_SIZE}); "
             "raising this holds InnoDB row locks for longer",
    )
    parser.add_argument(
        "--start-after",
        default="",
        help="resume after this IOC id (from an interrupted run's final line)",
    )
    parser.add_argument(
        "--verbose",
        action="store_true",
        help="log every chunk rather than just the first",
    )
    args = parser.parse_args(list(argv) if argv is not None else None)

    if args.chunk_size < 1:
        parser.error("--chunk-size must be at least 1")

    session = SyncSessionLocal()
    rescorer = Rescorer(
        session,
        chunk_size=args.chunk_size,
        dry_run=args.dry_run,
        verbose=args.verbose,
    )
    try:
        rescorer.run(start_after=args.start_after)
    except KeyboardInterrupt:
        print(f"\ninterrupted — resume with --start-after {rescorer.last_id}")
        rescorer.report()
        return 130
    finally:
        session.close()

    rescorer.report()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
