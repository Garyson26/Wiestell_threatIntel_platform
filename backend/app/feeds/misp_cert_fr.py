"""
MISP CERT-FR feed connector.

Fetches MD5 hashes from French ANSSI (CERT-FR) government incident response
cases published via MISP. Each hash is paired with a MISP event UUID that
groups related IOCs from the same investigation.

Source: https://misp.cert.ssi.gouv.fr/feed-misp/hashes.csv
"""

import csv
import logging
from typing import Any, Dict, List

from app.feeds.base import FULL_LIST_CUMULATIVE, BaseFeed

logger = logging.getLogger(__name__)

_FEED_URL = "https://misp.cert.ssi.gouv.fr/feed-misp/hashes.csv"
_TAGS = ["misp", "cert-fr", "anssi", "government-ir"]


class MISPCertFRFeed(BaseFeed):
    """Feed connector for MISP CERT-FR (French government IR hashes)."""

    name = "MISP CERT-FR"
    slug = "misp-cert-fr"
    feed_type = "csv"
    url = _FEED_URL
    description = (
        "MD5 hashes from French ANSSI/CERT-FR government incident response cases"
    )
    requires_api_key = False
    # Whole list republished every sync, no per-record timestamps.
    # 2,277 MD5 hashes measured 2026-07-31. Verified cumulative: the MISP manifest
    # holds 18 events spanning 2020-2024 and the CSV has no date column.
    # See BaseFeed.full_list_kind for what each kind does.
    full_list_kind = FULL_LIST_CUMULATIVE
    default_sync_frequency = 21600  # 6 hours

    async def fetch(self) -> str:
        """GET the CERT-FR hashes CSV."""
        response = await self._fetch_url(_FEED_URL)
        return response.text

    async def parse(self, raw: str) -> List[Dict[str, Any]]:
        """Parse CSV of md5_hash,misp_event_uuid into normalised IOC dicts."""
        seen: set[str] = set()
        iocs: List[Dict[str, Any]] = []

        lines = [
            line for line in raw.splitlines()
            if line.strip() and not line.strip().startswith("#")
        ]
        if not lines:
            return []

        reader = csv.reader(lines)
        for row in reader:
            if len(row) < 2:
                continue

            md5_hash = row[0].strip().lower()
            event_uuid = row[1].strip()

            if not md5_hash:
                continue

            dedup_key = f"hash:{md5_hash}"
            if dedup_key in seen:
                continue
            seen.add(dedup_key)

            iocs.append(self._make_ioc(
                ioc_type="hash",
                value=md5_hash,
                confidence=85,
                tags=list(_TAGS),
                metadata={
                    "source": "misp-cert-fr",
                    "misp_event_uuid": event_uuid,
                    "hash_type": "md5",
                },
            ))

        logger.info("%s: parsed %d hash(es)", self.name, len(iocs))
        return iocs
