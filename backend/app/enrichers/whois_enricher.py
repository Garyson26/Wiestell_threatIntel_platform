"""WHOIS enrichment for IPs, domains, URLs and email domains."""

import asyncio
from typing import Any, Dict, Optional

from app.config import settings
from app.enrichers.base import BaseEnricher


class WhoisEnricher(BaseEnricher):
    """Registration metadata lookup.

    The `whois` library is synchronous and network-bound, so the call is pushed
    to the default thread pool — running it inline would block the event loop
    for the duration of the query.
    """

    name = "whois"

    @property
    def cache_ttl(self) -> int:
        return settings.CACHE_TTL_WHOIS

    def supports(self, ioc_type: str) -> bool:
        return ioc_type in {"ip", "domain", "url", "email"}

    async def enrich(self, value: str, ioc_type: str) -> Optional[Dict[str, Any]]:
        def _blocking_whois(v: str) -> Dict[str, Any]:
            try:
                import whois
                w = whois.whois(v)
                creation = str(w.creation_date) if w.creation_date else None
                # Two signals, assessed independently: whether the registrant is
                # privacy-shielded is answerable from any record that came back, but
                # domain age needs a creation date. A record without one assesses only
                # the first, rather than charging the denominator for both.
                assessed = ["privacy_protected"]
                if creation:
                    assessed.append("domain_age")
                return {
                    "registrar": w.registrar,
                    "creation_date": creation,
                    "expiration_date": str(w.expiration_date) if w.expiration_date else None,
                    "name_servers": list(w.name_servers) if w.name_servers else [],
                    "registrant": w.org,
                    "country": w.country,
                    "privacy_protected": (
                        "privacy" in str(w.org or "").lower()
                        or "redacted" in str(w.org or "").lower()
                    ),
                    "assessed": assessed,
                }
            except Exception as exc:
                return {"error": f"WHOIS lookup failed: {str(exc)}"}

        loop = asyncio.get_event_loop()
        return await loop.run_in_executor(None, _blocking_whois, value)
