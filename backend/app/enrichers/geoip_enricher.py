"""GeoIP enrichment using the MaxMind GeoLite2 database."""

from typing import Any, Dict, Optional

import structlog

from app.config import settings
from app.enrichers.base import BaseEnricher

logger = structlog.get_logger()


class GeoIPEnricher(BaseEnricher):
    """Location and ASN lookup for IP addresses (local MaxMind database)."""

    name = "geoip"

    @property
    def cache_ttl(self) -> int:
        return settings.CACHE_TTL_GEOIP

    def supports(self, ioc_type: str) -> bool:
        return ioc_type == "ip"

    async def enrich(self, value: str, ioc_type: str) -> Optional[Dict[str, Any]]:
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

        # `high_risk_country` is assessable only when a country actually resolved. The
        # MaxMind file is often absent (GEOIP_DB_PATH defaults to a container path), in
        # which case the inner handler above writes `error_city` and country_code stays
        # None — a failed lookup, not a low-risk country.
        result["assessed"] = ["high_risk_country"] if result.get("country_code") else []
        return result
