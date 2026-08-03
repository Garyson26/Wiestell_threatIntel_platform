"""DNS enrichment: reverse PTR for IPs, forward records for domains and URLs."""

from typing import Any, Dict, List, Optional

from app.config import settings
from app.enrichers.base import BaseEnricher


class DNSEnricher(BaseEnricher):
    """Resolves A/AAAA/MX/NS/TXT for names, and PTR for addresses."""

    name = "dns"

    @property
    def cache_ttl(self) -> int:
        return settings.CACHE_TTL_DNS

    def supports(self, ioc_type: str) -> bool:
        return ioc_type in {"ip", "domain", "url"}

    async def enrich(self, value: str, ioc_type: str = "domain") -> Optional[Dict[str, Any]]:
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
                    # A reverse lookup says nothing about fast flux — that needs an
                    # A-record set. Declaring nothing is the whole point: this shape
                    # used to charge 2 denominator points against 0 risk for every IP.
                    "assessed": [],
                }

            # Domain / URL: forward DNS
            records: Dict[str, list] = {}
            for rtype in ["A", "AAAA", "MX", "NS", "TXT"]:
                try:
                    answers = dns.resolver.resolve(value, rtype)
                    records[rtype] = [str(r) for r in answers]
                except Exception:
                    records[rtype] = []

            # Every rtype above is caught into an empty list on failure, so `records`
            # is a truthy dict even when nothing resolved. Only a lookup that actually
            # returned something has assessed fast flux; an NXDOMAIN domain has not
            # been cleared of it.
            resolved = any(records.get(r) for r in ("A", "AAAA", "MX", "NS", "TXT"))
            return {
                "type": "forward",
                "records": records,
                "has_ipv6": bool(records.get("AAAA")),
                "nameservers": records.get("NS", []),
                "mail_servers": records.get("MX", []),
                "fast_flux": len(records.get("A", [])) > 5,
                "assessed": ["fast_flux"] if resolved else [],
            }
        except Exception as e:
            return {"error": f"DNS lookup failed: {str(e)}"}
