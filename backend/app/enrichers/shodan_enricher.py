"""Shodan enrichment for IPs."""

from typing import Dict, Any, Optional

from app.enrichers.base import BaseEnricher
from app.config import settings


class ShodanEnricher(BaseEnricher):
    name = "shodan"

    async def enrich(self, value: str, ioc_type: str) -> Optional[Dict[str, Any]]:
        if ioc_type != "ip":
            return None
        if not settings.SHODAN_API_KEY:
            return {"error": "Shodan API key not configured"}

        try:
            import shodan
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
            }
        except Exception as e:
            return {"error": str(e)}
