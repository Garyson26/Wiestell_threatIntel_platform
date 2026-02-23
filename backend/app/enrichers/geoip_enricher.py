"""GeoIP enrichment using MaxMind GeoLite2 database."""

from typing import Dict, Any, Optional

from app.enrichers.base import BaseEnricher
from app.config import settings


class GeoIPEnricher(BaseEnricher):
    name = "geoip"

    async def enrich(self, value: str, ioc_type: str) -> Optional[Dict[str, Any]]:
        if ioc_type != "ip":
            return None

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
            }
        except Exception:
            return {"country": "Unknown", "country_code": "XX", "error": "GeoIP DB not available"}
