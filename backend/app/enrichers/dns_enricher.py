"""DNS enrichment for domains."""

from typing import Dict, Any, Optional

from app.enrichers.base import BaseEnricher


class DNSEnricher(BaseEnricher):
    name = "dns"

    async def enrich(self, value: str, ioc_type: str) -> Optional[Dict[str, Any]]:
        if ioc_type not in ("domain", "url"):
            return None

        # Extract domain from URL if needed
        domain = value
        if ioc_type == "url":
            from urllib.parse import urlparse
            parsed = urlparse(value)
            domain = parsed.hostname or value

        try:
            import dns.resolver
            records = {}
            for rtype in ["A", "AAAA", "MX", "NS", "TXT"]:
                try:
                    answers = dns.resolver.resolve(domain, rtype)
                    records[rtype] = [str(r) for r in answers]
                except Exception:
                    records[rtype] = []

            return {
                "records": records,
                "has_ipv6": bool(records.get("AAAA")),
                "nameservers": records.get("NS", []),
                "fast_flux": len(records.get("A", [])) > 5,
            }
        except Exception as e:
            return {"error": str(e)}
