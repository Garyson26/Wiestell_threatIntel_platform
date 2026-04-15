#!/usr/bin/env python3
"""
Enrichment backfill script.

Checks every IOC in the database.  If an IOC has NO enrichment rows stored,
it fetches enrichment data from all applicable sources and writes the results
to the enrichments table.

Usage
-----
# Enrich all IOCs that have no enrichment data at all (default):
    python scripts/enrich_missing.py

# Preview how many IOCs need enrichment without actually enriching:
    python scripts/enrich_missing.py --dry-run

# Process at most N IOCs then stop:
    python scripts/enrich_missing.py --limit 200

# Re-enrich IOCs even if they already have data (full refresh):
    python scripts/enrich_missing.py --force

# Enrich a single IOC by its DB UUID:
    python scripts/enrich_missing.py --ioc-id <uuid>

# Filter to a specific IOC type only:
    python scripts/enrich_missing.py --ioc-type ip
    python scripts/enrich_missing.py --ioc-type domain

Notes
-----
- Each IOC is enriched in its own DB session + commit so a single failure
  never rolls back the whole run.
- Enrichment is skipped (not an error) if the enricher returns no data for
  an IOC type (e.g., GeoIP only applies to IP addresses).
- The script connects to the same database as the FastAPI app via
  app/config.py → DATABASE_ASYNC_URL.
"""

import sys
import os
import asyncio
import argparse
from datetime import datetime, timezone

# ── Make backend importable ───────────────────────────────────────────────────
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "backend"))

from sqlalchemy import select, func
from sqlalchemy.orm import selectinload

from app.database import AsyncSessionLocal
from app.models.ioc import IOC
from app.models.enrichment import Enrichment
from app.services.enrichment_engine import enrich_ioc, _get_applicable_sources


# ── Helpers ───────────────────────────────────────────────────────────────────

def _now() -> datetime:
    return datetime.now(timezone.utc).replace(tzinfo=None)


def _log(msg: str) -> None:
    """Print with immediate flush so output appears in real time."""
    print(msg, flush=True)


# ── DB queries ────────────────────────────────────────────────────────────────

async def count_total_iocs(ioc_type: str = None) -> int:
    async with AsyncSessionLocal() as session:
        q = select(func.count(IOC.id))
        if ioc_type:
            q = q.where(IOC.type == ioc_type)
        result = await session.execute(q)
        return result.scalar_one()


async def count_unenriched_iocs(ioc_type: str = None) -> int:
    async with AsyncSessionLocal() as session:
        q = (
            select(func.count(IOC.id))
            .outerjoin(Enrichment, IOC.id == Enrichment.ioc_id)
            .where(Enrichment.id.is_(None))
        )
        if ioc_type:
            q = q.where(IOC.type == ioc_type)
        result = await session.execute(q)
        return result.scalar_one()


async def fetch_ioc_batch(
    offset: int,
    batch_size: int,
    ioc_type: str = None,
    force: bool = False,
) -> list:
    """Return a list of (id, type, value) tuples for the next batch."""
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
        q = q.offset(offset).limit(batch_size)
        result = await session.execute(q)
        return result.fetchall()


# ── Core enrichment logic ─────────────────────────────────────────────────────

async def enrich_one(ioc_id: str) -> dict:
    """
    Enrich a single IOC (looked up by id) in its own session.
    Returns a status dict: {"ok": bool, "sources": int, "skipped": bool, "error": str|None}
    """
    async with AsyncSessionLocal() as session:
        result = await session.execute(select(IOC).where(IOC.id == ioc_id))
        ioc = result.scalar_one_or_none()
        if not ioc:
            return {"ok": False, "sources": 0, "skipped": False, "error": "IOC not found"}

        applicable = _get_applicable_sources(ioc.type)
        if not applicable:
            return {"ok": True, "sources": 0, "skipped": True, "error": None}

        try:
            enrichments = await enrich_ioc(session, ioc)
            await session.commit()
            return {"ok": True, "sources": len(enrichments), "skipped": False, "error": None}
        except Exception as exc:
            await session.rollback()
            return {"ok": False, "sources": 0, "skipped": False, "error": str(exc)}


# ── Main routines ─────────────────────────────────────────────────────────────

async def run_single(ioc_id: str) -> None:
    _log(f"\n🔍 Enriching IOC: {ioc_id}")
    r = await enrich_one(ioc_id)
    if r["error"]:
        _log(f"   ❌ {r['error']}")
    elif r["skipped"]:
        _log("   ⚠️  No applicable enrichment sources for this IOC type")
    else:
        _log(f"   ✅ Stored enrichment from {r['sources']} source(s)")


async def run_bulk(
    limit: int = None,
    force: bool = False,
    dry_run: bool = False,
    ioc_type: str = None,
) -> None:
    _log("\n📡 Connecting to database…")

    total_iocs = await count_total_iocs(ioc_type)
    unenriched = await count_unenriched_iocs(ioc_type) if not force else total_iocs

    type_label = f" ({ioc_type})" if ioc_type else ""
    _log(f"📊 Total IOCs{type_label}         : {total_iocs:,}")
    _log(f"📊 Unenriched IOCs{type_label}    : {unenriched:,}")

    to_process = unenriched if not limit else min(unenriched, limit)
    _log(f"📊 Will process               : {to_process:,}")

    if to_process == 0:
        _log("\n✅ All IOCs already have enrichment data. Nothing to do.")
        return

    if dry_run:
        _log("\n🔎 Dry-run mode — no changes written.")
        return

    _log("\n" + "─" * 55)

    BATCH = 50          # rows fetched per DB round-trip
    done = 0
    success = 0
    skipped = 0
    failed = 0
    offset = 0          # only used in force mode (no natural filter offset needed)

    start = _now()

    while done < to_process:
        # In normal (non-force) mode the query always fetches the "first"
        # unenriched rows — already-enriched rows drop out of the result set
        # after each iteration — so offset stays 0.
        # In force mode all IOCs qualify, so we advance the offset.
        batch_rows = await fetch_ioc_batch(
            offset=offset if force else 0,
            batch_size=min(BATCH, to_process - done),
            ioc_type=ioc_type,
            force=force,
        )

        if not batch_rows:
            break  # no more rows

        for row in batch_rows:
            ioc_id, ioc_type_val, ioc_value = row[0], row[1], row[2]
            done += 1
            _log(f"  [{done:>5}/{to_process}] {ioc_type_val:<8} {ioc_value}")

            r = await enrich_one(str(ioc_id))

            if r["error"]:
                failed += 1
                _log(f"           ❌ {r['error']}")
            elif r["skipped"]:
                skipped += 1
                _log(f"           ⚠️  Skipped (no sources for type '{ioc_type_val}')")
            else:
                success += 1
                _log(f"           ✅ {r['sources']} source(s) stored")

        if force:
            offset += len(batch_rows)

    elapsed = (_now() - start).total_seconds()

    _log("\n" + "─" * 55)
    _log(f"✅ Successfully enriched : {success:,}")
    _log(f"⚠️  Skipped (no sources) : {skipped:,}")
    _log(f"❌ Failed                : {failed:,}")
    _log(f"⏱  Time elapsed          : {elapsed:.1f}s")


# ── Entry point ───────────────────────────────────────────────────────────────

async def main() -> None:
    parser = argparse.ArgumentParser(
        description="Enrich IOCs that have no enrichment data in the database."
    )
    parser.add_argument(
        "--ioc-id",
        metavar="UUID",
        help="Enrich one specific IOC by its database UUID.",
    )
    parser.add_argument(
        "--ioc-type",
        metavar="TYPE",
        choices=["ip", "domain", "url", "hash", "email", "cve"],
        help="Only process IOCs of this type (ip, domain, url, hash, email, cve).",
    )
    parser.add_argument(
        "--limit",
        type=int,
        metavar="N",
        help="Stop after enriching N IOCs.",
    )
    parser.add_argument(
        "--force",
        action="store_true",
        help="Re-enrich IOCs even if enrichment data already exists.",
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Show counts only; do not write anything to the database.",
    )
    args = parser.parse_args()

    _log("=" * 55)
    _log("  SENTINEL — Enrichment Backfill")
    _log("=" * 55)

    if args.ioc_id:
        await run_single(args.ioc_id)
    else:
        await run_bulk(
            limit=args.limit,
            force=args.force,
            dry_run=args.dry_run,
            ioc_type=args.ioc_type,
        )

    _log("\n✨ Done!")


if __name__ == "__main__":
    asyncio.run(main())
