#!/usr/bin/env python3
"""
Manual script to trigger enrichment for IOCs.

Usage:
    # Enrich all IOCs without enrichment data:
    python scripts/trigger_enrichment.py

    # Enrich a specific IOC by ID:
    python scripts/trigger_enrichment.py --ioc-id <ioc_id>
    
    # Enrich up to N IOCs:
    python scripts/trigger_enrichment.py --limit 50
    
    # Force re-enrich even if data exists:
    python scripts/trigger_enrichment.py --force
"""

import sys
import os
import asyncio
import argparse
from datetime import datetime, timezone

# Add backend to path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'backend'))

from app.database import AsyncSessionLocal
from app.models.ioc import IOC
from app.models.enrichment import Enrichment
from app.services.enrichment_engine import enrich_ioc
from sqlalchemy import select, or_
from sqlalchemy.orm import selectinload


def _utcnow() -> datetime:
    """Return current UTC time as a timezone-naive datetime."""
    return datetime.now(timezone.utc).replace(tzinfo=None)


async def enrich_single_ioc(ioc_id: str):
    """Enrich a single IOC by ID."""
    async with AsyncSessionLocal() as session:
        result = await session.execute(
            select(IOC).options(selectinload(IOC.enrichments)).where(IOC.id == ioc_id)
        )
        ioc = result.scalar_one_or_none()
        
        if not ioc:
            print(f"❌ IOC not found: {ioc_id}")
            return False
        
        print(f"🔍 Enriching {ioc.type}: {ioc.value}")
        
        try:
            enrichments = await enrich_ioc(session, ioc)
            await session.commit()
            print(f"✅ Enriched with {len(enrichments)} sources")
            for e in enrichments:
                print(f"   - {e.get('source', 'unknown')}")
            return True
        except Exception as e:
            print(f"❌ Error: {str(e)}")
            await session.rollback()
            return False


async def find_unenriched_iocs(limit: int = None, force: bool = False):
    """Find IOCs that need enrichment."""
    async with AsyncSessionLocal() as session:
        if force:
            # Get all IOCs
            query = select(IOC.id, IOC.type, IOC.value)
            if limit:
                query = query.limit(limit)
        else:
            # Get IOCs with no enrichments or expired enrichments
            no_enrichment_query = (
                select(IOC.id, IOC.type, IOC.value)
                .outerjoin(Enrichment, IOC.id == Enrichment.ioc_id)
                .where(Enrichment.id.is_(None))
            )
            
            if limit:
                no_enrichment_query = no_enrichment_query.limit(limit)
            
            query = no_enrichment_query
        
        result = await session.execute(query)
        iocs = result.fetchall()
        return [(row[0], row[1], row[2]) for row in iocs]


async def enrich_iocs(limit: int = None, force: bool = False):
    """Find and enrich IOCs that need enrichment."""
    print("🔍 Finding IOCs that need enrichment...")
    
    iocs = await find_unenriched_iocs(limit=limit, force=force)
    
    if not iocs:
        print("✅ No IOCs found that need enrichment")
        return
    
    print(f"📊 Found {len(iocs)} IOC(s) to enrich\n")
    
    success_count = 0
    fail_count = 0
    
    for ioc_id, ioc_type, ioc_value in iocs:
        async with AsyncSessionLocal() as session:
            try:
                result = await session.execute(
                    select(IOC).where(IOC.id == ioc_id)
                )
                ioc = result.scalar_one_or_none()
                
                if ioc:
                    print(f"🔍 [{success_count + fail_count + 1}/{len(iocs)}] Enriching {ioc_type}: {ioc_value}")
                    enrichments = await enrich_ioc(session, ioc)
                    await session.commit()
                    
                    if enrichments:
                        print(f"   ✅ Enriched with {len(enrichments)} source(s)")
                        success_count += 1
                    else:
                        print(f"   ⚠️  No enrichment data available for this IOC type")
                        fail_count += 1
            except Exception as e:
                print(f"   ❌ Error: {str(e)}")
                fail_count += 1
                await session.rollback()
    
    print(f"\n📊 Summary:")
    print(f"   ✅ Successfully enriched: {success_count}")
    print(f"   ❌ Failed or skipped: {fail_count}")
    print(f"   📈 Total processed: {len(iocs)}")


async def main():
    parser = argparse.ArgumentParser(description="Trigger IOC enrichment")
    parser.add_argument("--ioc-id", help="Enrich a specific IOC by ID")
    parser.add_argument("--limit", type=int, help="Maximum number of IOCs to enrich")
    parser.add_argument("--force", action="store_true", help="Re-enrich even if data exists")
    
    args = parser.parse_args()
    
    print("🚀 IOC Enrichment Script")
    print("=" * 50)
    
    if args.ioc_id:
        await enrich_single_ioc(args.ioc_id)
    else:
        await enrich_iocs(limit=args.limit, force=args.force)
    
    print("\n✨ Done!")


if __name__ == "__main__":
    asyncio.run(main())
