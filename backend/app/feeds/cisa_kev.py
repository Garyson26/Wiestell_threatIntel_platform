"""
CISA KEV feed connector.

Fetches the Known Exploited Vulnerabilities catalog from CISA via the
GitHub mirror (direct CISA URLs return 403 from Cloudflare).

Source: https://github.com/cisagov/kev-data
License: CC0 (public domain)
"""

import logging
from datetime import datetime
from typing import Any, Dict, List, Optional

from app.feeds.base import BaseFeed, SHAPE_CUMULATIVE_CATALOGUE

logger = logging.getLogger(__name__)


def _parse_kev_date(value: Optional[str]) -> Optional[datetime]:
    """CISA's ``dateAdded`` / ``dueDate``, which are plain ``YYYY-MM-DD``.

    Returns None on anything unparseable rather than guessing. A None flows into
    ``_make_ioc``, which defaults to ``now()`` — the pre-2026-08-17 behaviour — so a
    format change degrades to what we had rather than to a crash or a wrong date.
    Timezone-naive UTC to match the column convention; a date has no time-of-day, so
    midnight UTC is the only honest reading of it.
    """
    if not value:
        return None
    try:
        return datetime.strptime(value.strip(), "%Y-%m-%d")
    except (ValueError, AttributeError):
        logger.warning("cisa_kev_unparseable_date value=%r", value)
        return None

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
    source_shape = SHAPE_CUMULATIVE_CATALOGUE
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

        # `dateAdded` was parsed into metadata and then dropped on the floor. Because
        # `_make_ioc` defaults an absent stamp to now(), `last_seen` recorded the date WE
        # ingested the entry rather than the date CISA added it — for a catalogue going
        # back to 2021, potentially years off. Fixed 2026-08-17 (Phase 4 Section C).
        #
        # This does NOT unfreeze the counter. `dateAdded` never moves for an existing
        # entry, so the re-read gate still never fires and CUMULATIVE_CATALOGUE still
        # freezes both stamps. What changes is that recency is now ACCURATE: a KEV CVE
        # added last week reads fresh and a 2021 entry decays correctly, instead of every
        # entry looking as though it were first seen on the day we happened to sync.
        #
        # That is the difference between "frozen because we have no information" and
        # "frozen because the source says nothing changed".
        added = _parse_kev_date(entry.get("dateAdded"))

        return self._make_ioc(
            ioc_type="cve",
            value=cve_id,
            confidence=95,
            tags=tags,
            metadata=metadata,
            first_seen=added,
            last_seen=added,
        )
