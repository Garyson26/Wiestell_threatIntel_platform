"""
Wiestell — CVE Details REST API enricher.

Enriches CVE IOCs with multi-source CVSS scores, advisories, exploit
availability data from CVE Details.

Requires paid subscription. If CVEDETAILS_ACCESS_TOKEN is not configured,
this enricher is not loaded into the engine.

API docs: https://www.cvedetails.com/api/documentation
Rate limits: Organisation-level. HTTP 429 → wait 60 seconds.
"""

import asyncio
import logging
from typing import Any, Optional

from app.enrichers.base import BaseEnricher

logger = logging.getLogger(__name__)

_API_BASE = "https://www.cvedetails.com/api/v1"
_SUPPORTED_TYPES = {"cve"}


class CVEDetailsEnricher(BaseEnricher):
    """CVE Details API enricher for CVE IOCs."""

    name = "cvedetails"
    cache_ttl = 86400  # 24 hours

    def __init__(self, access_token: str) -> None:
        self.access_token = access_token

    def supports(self, ioc_type: str) -> bool:
        return ioc_type in _SUPPORTED_TYPES

    async def enrich(self, value: str, ioc_type: str) -> Optional[dict[str, Any]]:
        """Query CVE Details API for the given CVE ID.

        Never raises — HTTP and parsing errors are returned as
        {"source": "cvedetails", "error": "..."} dicts.
        Retries once on HTTP 429 after a 60-second wait.
        """
        import httpx

        headers = {"Authorization": f"Bearer {self.access_token}"}

        try:
            async with httpx.AsyncClient(timeout=30.0) as client:
                resp = await client.get(
                    f"{_API_BASE}/vulnerability/search",
                    params={"cveId": value},
                    headers=headers,
                )

                # Retry on 429 (rate limit) — wait 60s, try once more
                if resp.status_code == 429:
                    logger.warning("CVE Details rate limited (429) — waiting 60s")
                    await asyncio.sleep(60)
                    resp = await client.get(
                        f"{_API_BASE}/vulnerability/search",
                        params={"cveId": value},
                        headers=headers,
                    )

                resp.raise_for_status()
                body = resp.json()
                return self._extract(body)

        except Exception as exc:
            logger.warning("CVE Details enrichment failed for %s: %s", value, exc)
            return {"source": "cvedetails", "error": str(exc)}

    def _extract(self, body: dict) -> dict[str, Any]:
        """Extract enrichment fields from CVE Details response."""
        results_list = body.get("results") or []
        if not results_list:
            return {"source": "cvedetails", "found": False}

        entry = results_list[0]

        # Multi-source CVSS scores
        cvss_scores: dict[str, Any] = {}
        nvd_score = entry.get("cvssV3Score")
        if nvd_score is not None:
            cvss_scores["nvd"] = nvd_score
        vendor_score = entry.get("vendorCvssV3Score")
        if vendor_score is not None:
            cvss_scores["vendor"] = vendor_score

        # Advisories
        advisories: list[str] = []
        for adv in entry.get("advisories") or []:
            url = adv.get("url", "")
            if url:
                advisories.append(url)

        # Exploit references
        exploit_refs: list[str] = []
        for ref in entry.get("exploitReferences") or []:
            url = ref.get("url", "")
            if url:
                exploit_refs.append(url)

        # Affected products
        affected: list[dict[str, str]] = []
        for prod in entry.get("affectedProducts") or []:
            affected.append({
                "vendor": prod.get("vendor", ""),
                "product": prod.get("product", ""),
            })

        return {
            "source": "cvedetails",
            # A record came back, so both exploit signals were answered — including
            # "no public exploit", which is real evidence of lower risk rather than an
            # absence. The `{"found": False}` and `{"error": ...}` shapes above return
            # before reaching here and declare nothing.
            "assessed": ["exploit_available", "exploit_references"],
            "cvedetails_cvss_scores": cvss_scores,
            "cvedetails_advisories": advisories,
            "cvedetails_exploit_available": entry.get("exploitAvailable", False),
            "cvedetails_exploit_references": exploit_refs,
            "cvedetails_affected_products": affected,
        }