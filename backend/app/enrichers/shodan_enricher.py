"""Shodan enrichment for IP addresses."""

from typing import Any, Dict, Optional

from app.config import settings
from app.enrichers.base import BaseEnricher


class ShodanEnricher(BaseEnricher):
    """Exposed ports, services and known vulnerabilities for an IP.

    Unlike the credential-gated enrichers this one stays registered without a
    key, returning an explanatory payload — preserving the pre-consolidation
    behaviour where `shodan` was always an applicable source for IPs.
    """

    name = "shodan"
    cache_ttl = 21600  # 6 hours — port scans and vuln data change moderately

    def supports(self, ioc_type: str) -> bool:
        return ioc_type == "ip"

    async def enrich(self, value: str, ioc_type: str) -> Optional[Dict[str, Any]]:
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
        except shodan.APIError as e:
            error_msg = str(e)
            # Return a generic message: upstream error text can echo the key.
            if "403" in error_msg or "Forbidden" in error_msg:
                return {"error": "Shodan service unavailable"}
            elif "401" in error_msg or "Unauthorized" in error_msg:
                return {"error": "Shodan authentication failed"}
            elif "No information available" in error_msg:
                return {"error": "No Shodan data available"}
            else:
                return {"error": "Shodan lookup failed"}
        except Exception:
            return {"error": "Shodan lookup failed"}
