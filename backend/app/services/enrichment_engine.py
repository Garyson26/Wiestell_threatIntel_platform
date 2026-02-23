"""Multi-source enrichment orchestrator for IOCs."""

import asyncio
from datetime import datetime, timezone, timedelta
from typing import Dict, Any, List, Optional

from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select

from app.models.ioc import IOC
from app.models.enrichment import Enrichment
from app.config import settings

import structlog

logger = structlog.get_logger()


async def enrich_ioc(
    session: AsyncSession,
    ioc: IOC,
    sources: Optional[List[str]] = None,
) -> List[Dict[str, Any]]:
    """Run enrichment pipeline for an IOC.
    
    Runs applicable enrichers in parallel and stores results.
    """
    if sources is None:
        sources = _get_applicable_sources(ioc.type)

    results = []
    tasks = []

    for source in sources:
        cached = await _get_cached_enrichment(session, ioc.id, source)
        if cached:
            results.append(cached)
            continue
        tasks.append(_run_enricher(source, ioc))

    if tasks:
        enrichment_results = await asyncio.gather(*tasks, return_exceptions=True)
        
        for source, result in zip(
            [s for s in sources if not await _get_cached_enrichment(session, ioc.id, s)],
            enrichment_results,
        ):
            if isinstance(result, Exception):
                logger.error("enrichment_failed", source=source, ioc=ioc.value, error=str(result))
                continue
            
            if result:
                ttl = _get_ttl(source)
                enrichment = Enrichment(
                    ioc_id=ioc.id,
                    source=source,
                    data=result,
                    enriched_at=datetime.now(timezone.utc),
                    expires_at=datetime.now(timezone.utc) + timedelta(seconds=ttl),
                )
                
                existing = await session.execute(
                    select(Enrichment).where(
                        Enrichment.ioc_id == ioc.id,
                        Enrichment.source == source,
                    )
                )
                existing_record = existing.scalar_one_or_none()
                if existing_record:
                    existing_record.data = result
                    existing_record.enriched_at = datetime.now(timezone.utc)
                    existing_record.expires_at = datetime.now(timezone.utc) + timedelta(seconds=ttl)
                else:
                    session.add(enrichment)
                
                results.append({"source": source, "data": result})

    await session.flush()
    return results


def _get_applicable_sources(ioc_type: str) -> List[str]:
    """Determine which enrichment sources apply to an IOC type."""
    source_map = {
        "ip": ["geoip", "whois", "dns", "reputation"],
        "domain": ["whois", "dns", "reputation"],
        "url": ["whois", "dns", "reputation"],
        "hash": ["reputation"],
        "email": ["whois", "reputation"],
        "cve": ["reputation"],
    }
    return source_map.get(ioc_type, ["reputation"])


async def _get_cached_enrichment(
    session: AsyncSession, ioc_id, source: str
) -> Optional[Dict]:
    """Check if valid cached enrichment exists."""
    result = await session.execute(
        select(Enrichment).where(
            Enrichment.ioc_id == ioc_id,
            Enrichment.source == source,
        )
    )
    enrichment = result.scalar_one_or_none()
    
    if enrichment and enrichment.expires_at:
        if enrichment.expires_at > datetime.now(timezone.utc):
            return {"source": source, "data": enrichment.data}
    
    return None


async def _run_enricher(source: str, ioc: IOC) -> Optional[Dict]:
    """Run a specific enricher for an IOC."""
    try:
        if source == "geoip":
            return await _enrich_geoip(ioc.value)
        elif source == "whois":
            return await _enrich_whois(ioc.value, ioc.type)
        elif source == "dns":
            return await _enrich_dns(ioc.value)
        elif source == "reputation":
            return await _enrich_reputation(ioc.value, ioc.type)
        else:
            return None
    except Exception as e:
        logger.error("enricher_error", source=source, error=str(e))
        return None


async def _enrich_geoip(value: str) -> Optional[Dict]:
    """GeoIP enrichment - returns location data for an IP."""
    try:
        import geoip2.database
        reader = geoip2.database.Reader(settings.GEOIP_DB_PATH)
        response = reader.city(value)
        return {
            "country": response.country.name,
            "country_code": response.country.iso_code,
            "city": response.city.name,
            "latitude": response.location.latitude,
            "longitude": response.location.longitude,
            "asn": None,
            "isp": None,
        }
    except Exception:
        return {
            "country": "Unknown",
            "country_code": "XX",
            "city": None,
            "latitude": None,
            "longitude": None,
            "asn": None,
            "isp": None,
            "error": "GeoIP database not available",
        }


async def _enrich_whois(value: str, ioc_type: str) -> Optional[Dict]:
    """WHOIS enrichment for domains and IPs."""
    try:
        import whois
        w = whois.whois(value)
        return {
            "registrar": w.registrar,
            "creation_date": str(w.creation_date) if w.creation_date else None,
            "expiration_date": str(w.expiration_date) if w.expiration_date else None,
            "name_servers": w.name_servers if w.name_servers else [],
            "registrant": w.org,
            "country": w.country,
            "privacy_protected": "privacy" in str(w.org or "").lower() or "redacted" in str(w.org or "").lower(),
        }
    except Exception as e:
        return {"error": f"WHOIS lookup failed: {str(e)}"}


async def _enrich_dns(value: str) -> Optional[Dict]:
    """DNS enrichment for domains."""
    try:
        import dns.resolver
        records = {}
        
        for rtype in ["A", "AAAA", "MX", "NS", "TXT"]:
            try:
                answers = dns.resolver.resolve(value, rtype)
                records[rtype] = [str(r) for r in answers]
            except Exception:
                records[rtype] = []
        
        return {
            "records": records,
            "has_ipv6": bool(records.get("AAAA")),
            "nameservers": records.get("NS", []),
            "mail_servers": records.get("MX", []),
            "fast_flux": len(records.get("A", [])) > 5,
        }
    except Exception as e:
        return {"error": f"DNS lookup failed: {str(e)}"}


async def _enrich_reputation(value: str, ioc_type: str) -> Optional[Dict]:
    """Aggregate reputation check across available sources."""
    return {
        "aggregate_score": 0,
        "sources_checked": 0,
        "sources_flagged": 0,
        "details": {},
        "note": "Enable feed API keys for live reputation checks",
    }


def _get_ttl(source: str) -> int:
    """Get cache TTL for an enrichment source."""
    ttl_map = {
        "whois": settings.CACHE_TTL_WHOIS,
        "dns": settings.CACHE_TTL_DNS,
        "geoip": settings.CACHE_TTL_GEOIP,
        "reputation": settings.CACHE_TTL_REPUTATION,
    }
    return ttl_map.get(source, 3600)
