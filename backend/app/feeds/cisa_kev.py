"""
CISA KEV feed connector.

Fetches the Known Exploited Vulnerabilities catalog from CISA via the
GitHub mirror (direct CISA URLs return 403 from Cloudflare).

Source: https://github.com/cisagov/kev-data
License: CC0 (public domain)
"""

import logging
from typing import Any, Dict, List, Optional

from app.feeds.base import FULL_LIST_CUMULATIVE, BaseFeed

logger = logging.getLogger(__name__)

_CATALOG_URL = (
    "https://raw.githubusercontent.com/cisagov/kev-data/"
    "develop/known_exploited_vulnerabilities.json"
)


class CISAKEVFeed(BaseFeed):
    """Feed connector for CISA Known Exploited Vulnerabilities."""

    name = "CISA KEV"
    slug = "cisa-kev"
    feed_type = "api"
    url = _CATALOG_URL
    description = (
        "CISA Known Exploited Vulnerabilities — CVEs with confirmed "
        "in-the-wild exploitation"
    )
    requires_api_key = False
    # Whole list republished every sync, no per-record timestamps.
    # 1,656 CVEs measured 2026-07-31. The KEV catalogue only grows; a CVE added in
    # 2021 is still listed, so presence today is not an observation today.
    # See BaseFeed.full_list_kind for what each kind does.
    full_list_kind = FULL_LIST_CUMULATIVE
    default_sync_frequency = 86400  # catalogue updates at most daily

    async def fetch(self) -> Dict[str, Any]:
        """GET the KEV JSON catalog from the GitHub mirror."""
        response = await self._fetch_url(_CATALOG_URL)
        return response.json()

    async def parse(self, raw: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Parse the KEV catalog into normalised CVE IOC dicts."""
        seen: set[str] = set()
        iocs: List[Dict[str, Any]] = []

        for entry in raw.get("vulnerabilities") or []:
            ioc = self._parse_entry(entry, seen)
            if ioc is not None:
                iocs.append(ioc)

        logger.info("%s: parsed %d CVE(s)", self.name, len(iocs))
        return iocs

    def _parse_entry(
        self, entry: Dict[str, Any], seen: set[str],
    ) -> Optional[Dict[str, Any]]:
        """Convert a single KEV entry to a CVE IOC dict, or None."""
        cve_id = (entry.get("cveID") or "").strip()
        if not cve_id:
            return None

        dedup_key = f"cve:{cve_id}"
        if dedup_key in seen:
            return None
        seen.add(dedup_key)

        vendor = (entry.get("vendorProject") or "").strip()
        ransomware_use = (entry.get("knownRansomwareCampaignUse") or "").strip()

        tags: list[str] = ["cisa-kev"]
        if vendor:
            tags.append(vendor.lower())
        if ransomware_use == "Known":
            tags.append("ransomware")

        metadata: dict[str, Any] = {
            "vendor":             vendor,
            "product":            (entry.get("product") or "").strip(),
            "vulnerability_name": (entry.get("vulnerabilityName") or "").strip(),
            "date_added":         (entry.get("dateAdded") or "").strip(),
            "due_date":           (entry.get("dueDate") or "").strip(),
            "required_action":    (entry.get("requiredAction") or "").strip(),
            "ransomware_use":     ransomware_use,
            "cwes":               entry.get("cwes") or [],
            "source":             "cisa-kev",
        }

        return self._make_ioc(
            ioc_type="cve",
            value=cve_id,
            confidence=95,
            tags=tags,
            metadata=metadata,
        )
