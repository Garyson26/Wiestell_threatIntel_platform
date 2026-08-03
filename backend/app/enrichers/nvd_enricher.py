"""
Wiestell — NVD API 2.0 enricher.

Enriches CVE IOCs with CVSS scores, CWE IDs, affected products (CPE),
descriptions, and vulnerability status from the NIST National Vulnerability
Database.

API docs: https://nvd.nist.gov/developers/vulnerabilities
Rate limits: 5 req/30s without key, 50 req/30s with key.

Attribution: "This product uses data from the NVD API but is not endorsed
or certified by the NVD."
"""

import logging
from typing import Any, Optional

from app.enrichers.base import BaseEnricher

logger = logging.getLogger(__name__)

_NVD_API_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
_SUPPORTED_TYPES = {"cve"}


class NVDEnricher(BaseEnricher):
    """NVD API 2.0 enricher for CVE IOCs."""

    name = "nvd"
    cache_ttl = 86400  # 24 hours

    def __init__(self, api_key: str | None = None) -> None:
        self.api_key = api_key

    def supports(self, ioc_type: str) -> bool:
        return ioc_type in _SUPPORTED_TYPES

    async def enrich(self, value: str, ioc_type: str) -> Optional[dict[str, Any]]:
        """Query NVD API for the given CVE ID.

        Never raises — HTTP and parsing errors are returned as
        {"source": "nvd", "error": "..."} dicts.
        """
        import httpx

        headers: dict[str, str] = {}
        if self.api_key:
            headers["apiKey"] = self.api_key

        try:
            async with httpx.AsyncClient(timeout=30.0) as client:
                resp = await client.get(
                    _NVD_API_URL,
                    params={"cveId": value},
                    headers=headers,
                )

                if resp.status_code == 404:
                    return {"source": "nvd", "found": False}

                resp.raise_for_status()
                body = resp.json()
                return self._extract(body)

        except Exception as exc:
            logger.warning("NVD enrichment failed for %s: %s", value, exc)
            return {"source": "nvd", "error": str(exc)}

    def _extract(self, body: dict) -> dict[str, Any]:
        """Extract enrichment fields from NVD API response."""
        vulns = body.get("vulnerabilities") or []
        if not vulns:
            return {"source": "nvd", "found": False}

        cve_data = vulns[0].get("cve", {})

        # CVSS v3.1
        cvss_score = None
        cvss_severity = None
        cvss_vector = None
        metrics = cve_data.get("metrics", {})
        cvss_list = metrics.get("cvssMetricV31") or []
        if cvss_list:
            cvss_data = cvss_list[0].get("cvssData", {})
            cvss_score = cvss_data.get("baseScore")
            cvss_severity = cvss_data.get("baseSeverity")
            cvss_vector = cvss_data.get("vectorString")

        # CWE IDs
        cwe_ids: list[str] = []
        for weakness in cve_data.get("weaknesses") or []:
            for desc in weakness.get("description") or []:
                cwe_val = desc.get("value", "")
                if cwe_val.startswith("CWE-"):
                    cwe_ids.append(cwe_val)

        # English description
        description = ""
        for desc in cve_data.get("descriptions") or []:
            if desc.get("lang") == "en":
                description = desc.get("value", "")
                break

        # Affected products (CPE)
        affected_products: list[str] = []
        for config in cve_data.get("configurations") or []:
            for node in config.get("nodes") or []:
                for match in node.get("cpeMatch") or []:
                    criteria = match.get("criteria", "")
                    if criteria:
                        affected_products.append(criteria)

        # KEV presence (NVD includes cisaExploitAdd if in KEV)
        in_kev = "cisaExploitAdd" in cve_data

        # Per-signal: an entry can carry a KEV determination without a CVSS v3.1
        # score (older CVEs frequently do). Charging all six denominator points for
        # three assessable ones gave 50.0 where 100.0 is correct — about 15 points of
        # composite under the `cve` weight profile.
        assessed = []
        if cvss_score is not None:
            assessed.append("cvss")
        # `in_kev` is a definite yes/no whenever NVD returned a record for the CVE.
        assessed.append("kev_membership")

        return {
            "source": "nvd",
            "assessed": assessed,
            "nvd_cvss_v31_score": cvss_score,
            "nvd_cvss_v31_severity": cvss_severity,
            "nvd_cvss_v31_vector": cvss_vector,
            "nvd_cwe_ids": cwe_ids,
            "nvd_description": description,
            "nvd_vuln_status": cve_data.get("vulnStatus"),
            "nvd_published": cve_data.get("published"),
            "nvd_affected_products": affected_products,
            "nvd_in_kev": in_kev,
        }
