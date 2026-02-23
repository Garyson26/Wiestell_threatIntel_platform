"""WHOIS enrichment for domains and IPs."""

from typing import Dict, Any, Optional

from app.enrichers.base import BaseEnricher


class WhoisEnricher(BaseEnricher):
    name = "whois"

    async def enrich(self, value: str, ioc_type: str) -> Optional[Dict[str, Any]]:
        if ioc_type not in ("domain", "ip"):
            return None

        try:
            import whois
            w = whois.whois(value)
            return {
                "registrar": w.registrar,
                "creation_date": str(w.creation_date) if w.creation_date else None,
                "expiration_date": str(w.expiration_date) if w.expiration_date else None,
                "name_servers": list(w.name_servers) if w.name_servers else [],
                "registrant_org": w.org,
                "country": w.country,
                "privacy_protected": "privacy" in str(w.org or "").lower(),
            }
        except Exception as e:
            return {"error": str(e)}
