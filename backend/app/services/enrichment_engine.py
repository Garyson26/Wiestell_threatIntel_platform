"""Multi-source enrichment orchestrator for IOCs."""

import asyncio
from datetime import datetime, timezone, timedelta
from typing import Dict, Any, List, Optional

from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select
from sqlalchemy.exc import IntegrityError

from app.models.ioc import IOC
from app.models.enrichment import Enrichment
from app.config import settings

import structlog

logger = structlog.get_logger()


def _utcnow() -> datetime:
    """Return current UTC time as a timezone-naive datetime for MySQL DateTime columns."""
    return datetime.now(timezone.utc).replace(tzinfo=None)


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

    # Pass 2: run all pending enrichers in parallel.
    enrichment_results = await asyncio.gather(
        *[_run_enricher(s, ioc) for s in pending_sources],
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
            return cached_results
    
    return results


def _get_applicable_sources(ioc_type: str) -> List[str]:
    """Determine which enrichment sources apply to an IOC type."""
    source_map = {
        "ip":     ["geoip", "whois", "dns", "reputation", "shodan"],
        "domain": ["whois", "dns", "reputation"],
        "url":    ["whois", "dns", "reputation"],
        "hash":   ["malwarebazaar", "reputation"],
        "email":  ["whois", "reputation"],
        "cve":    ["reputation"],
    }
    return source_map.get(ioc_type, ["reputation"])


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
    """Dispatch to the correct enricher; catches all exceptions so gather never raises."""
    try:
        if source == "geoip":
            return await _enrich_geoip(ioc.value)
        elif source == "whois":
            return await _enrich_whois(ioc.value, ioc.type)
        elif source == "dns":
            return await _enrich_dns(ioc.value, ioc.type)
        elif source == "reputation":
            return await _enrich_reputation(ioc.value, ioc.type)
        elif source == "shodan":
            return await _enrich_shodan(ioc.value)
        elif source == "malwarebazaar":
            return await _enrich_malwarebazaar(ioc.value)
        else:
            return None
    except Exception as e:
        logger.error("enricher_error", source=source, error=str(e))
        return None


async def _enrich_geoip(value: str) -> Optional[Dict]:
    """GeoIP enrichment — returns location + ASN data for an IP."""
    result: Dict[str, Any] = {
        "country": None, "country_code": None,
        "city": None, "latitude": None, "longitude": None,
        "asn": None, "asn_org": None,
    }
    try:
        import geoip2.database

        # City / location lookup
        try:
            reader = geoip2.database.Reader(settings.GEOIP_DB_PATH)
            city_resp = reader.city(value)
            reader.close()
            result.update({
                "country": city_resp.country.name,
                "country_code": city_resp.country.iso_code,
                "city": city_resp.city.name,
                "latitude": city_resp.location.latitude,
                "longitude": city_resp.location.longitude,
            })
        except Exception:
            result["error_city"] = "GeoIP city database not available"

        # ASN lookup — requires a separate MaxMind ASN database
        asn_db = getattr(settings, "GEOIP_ASN_DB_PATH", None)
        if asn_db:
            try:
                reader = geoip2.database.Reader(asn_db)
                asn_resp = reader.asn(value)
                reader.close()
                result.update({
                    "asn": asn_resp.autonomous_system_number,
                    "asn_org": asn_resp.autonomous_system_organization,
                })
            except Exception:
                pass

    except Exception as e:
        result["error"] = f"GeoIP lookup failed: {str(e)}"

    return result


async def _enrich_shodan(value: str) -> Optional[Dict]:
    """Shodan enrichment for IPs."""
    if not settings.SHODAN_API_KEY:
        return {"error": "Shodan API key not configured"}
    
    try:
        import shodan
    except ImportError:
        return {"error": "Shodan library not installed"}
    
    try:
        api = shodan.Shodan(settings.SHODAN_API_KEY)
        host = api.host(value)
        return {
            "ip": host.get("ip_str"),
            "org": host.get("org"),
            "os": host.get("os"),
            "ports": host.get("ports", []),
            "vulns": host.get("vulns", []),
            "hostnames": host.get("hostnames", []),
            "country": host.get("country_name"),
            "city": host.get("city"),
            "asn": host.get("asn"),
            "last_update": host.get("last_update"),
            "tags": host.get("tags", []),
        }
    except Exception as e:
        return {"error": str(e)}


async def _enrich_whois(value: str, ioc_type: str) -> Optional[Dict]:
    """WHOIS enrichment — offloaded to a thread pool to avoid blocking the event loop."""
    def _blocking_whois(v: str) -> Dict:
        try:
            import whois
            w = whois.whois(v)
            return {
                "registrar": w.registrar,
                "creation_date": str(w.creation_date) if w.creation_date else None,
                "expiration_date": str(w.expiration_date) if w.expiration_date else None,
                "name_servers": list(w.name_servers) if w.name_servers else [],
                "registrant": w.org,
                "country": w.country,
                "privacy_protected": (
                    "privacy" in str(w.org or "").lower()
                    or "redacted" in str(w.org or "").lower()
                ),
            }
        except Exception as exc:
            return {"error": f"WHOIS lookup failed: {str(exc)}"}

    loop = asyncio.get_event_loop()
    return await loop.run_in_executor(None, _blocking_whois, value)


async def _enrich_dns(value: str, ioc_type: str = "domain") -> Optional[Dict]:
    """DNS enrichment.

    For IP addresses performs a reverse PTR lookup (hostname resolution).
    For domains/URLs resolves A/AAAA/MX/NS/TXT records.
    """
    try:
        import dns.resolver
        import dns.reversename

        if ioc_type == "ip":
            ptr_records: List[str] = []
            try:
                rev_name = dns.reversename.from_address(value)
                answers = dns.resolver.resolve(rev_name, "PTR")
                ptr_records = [str(r) for r in answers]
            except Exception:
                pass
            return {
                "type": "reverse",
                "ptr": ptr_records,
                "hostname": ptr_records[0].rstrip(".") if ptr_records else None,
            }

        # Domain / URL: forward DNS
        records: Dict[str, list] = {}
        for rtype in ["A", "AAAA", "MX", "NS", "TXT"]:
            try:
                answers = dns.resolver.resolve(value, rtype)
                records[rtype] = [str(r) for r in answers]
            except Exception:
                records[rtype] = []

        return {
            "type": "forward",
            "records": records,
            "has_ipv6": bool(records.get("AAAA")),
            "nameservers": records.get("NS", []),
            "mail_servers": records.get("MX", []),
            "fast_flux": len(records.get("A", [])) > 5,
        }
    except Exception as e:
        return {"error": f"DNS lookup failed: {str(e)}"}


async def _enrich_malwarebazaar(value: str) -> Optional[Dict]:
    """Query MalwareBazaar for hash intelligence (MD5, SHA1, or SHA256)."""
    try:
        import httpx
        api_key = settings.MALWAREBAZAAR_API_KEY
        headers = {"Auth-Key": api_key} if api_key else {}
        async with httpx.AsyncClient(timeout=15) as client:
            response = await client.post(
                "https://mb-api.abuse.ch/api/v1/",
                data={"query": "get_info", "hash": value},
                headers=headers,
            )
            response.raise_for_status()
            data = response.json()

        status = data.get("query_status", "")
        if status != "ok" or not data.get("data"):
            return {"found": False, "query_status": status}

        entry = data["data"][0]
        return {
            "found": True,
            "sha256": entry.get("sha256_hash"),
            "sha1": entry.get("sha1_hash"),
            "md5": entry.get("md5_hash"),
            "file_name": entry.get("file_name"),
            "file_type": entry.get("file_type"),
            "file_type_mime": entry.get("file_type_mime"),
            "file_size": entry.get("file_size"),
            "signature": entry.get("signature"),
            "tags": entry.get("tags") or [],
            "reporter": entry.get("reporter"),
            "origin_country": entry.get("origin_country"),
            "first_seen": entry.get("first_seen"),
            "last_seen": entry.get("last_seen"),
            "delivery_method": entry.get("delivery_method"),
            "intelligence": entry.get("intelligence"),
            "vendor_intel": entry.get("vendor_intel"),
        }
    except Exception as e:
        logger.warning("malwarebazaar_enrichment_failed", hash=value[:16], error=str(e))
        return {"found": False, "error": str(e)}


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
    """Get cache TTL in seconds for an enrichment source."""
    ttl_map = {
        "whois":         settings.CACHE_TTL_WHOIS,
        "dns":           settings.CACHE_TTL_DNS,
        "geoip":         settings.CACHE_TTL_GEOIP,
        "reputation":    settings.CACHE_TTL_REPUTATION,
        "shodan":        21600,  # 6 hours — port scans and vuln data change moderately
        "malwarebazaar": 43200,  # 12 hours — hash intel changes infrequently
    }
    return ttl_map.get(source, 3600)
