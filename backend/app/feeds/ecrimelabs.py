"""
eCrimeLabs Metasploit CVE feed connector.

Fetches CVE IDs that have active Metasploit exploit modules.
Response may be gzipped — auto-detects and decompresses.

Source: https://feeds.ecrimelabs.net/data/metasploit-cve
"""

import gzip
import logging
import re
from typing import Any, Dict, List

from app.feeds.base import FULL_LIST_CUMULATIVE, BaseFeed

logger = logging.getLogger(__name__)

_FEED_URL = "https://feeds.ecrimelabs.net/data/metasploit-cve"
_CVE_RE = re.compile(r"^CVE-\d{4}-\d{4,}$", re.IGNORECASE)
_TAGS = ["ecrimelabs", "metasploit", "exploitable"]


class ECrimeLabsCVEFeed(BaseFeed):
    """Feed connector for eCrimeLabs Metasploit CVE list."""

    name = "eCrimeLabs Metasploit CVE"
    slug = "ecrimelabs-metasploit"
    feed_type = "csv"
    url = _FEED_URL
    description = "CVEs with a public Metasploit exploit module"
    requires_api_key = False
    # Whole list republished every sync, no per-record timestamps.
    # 3,195 CVEs measured 2026-07-31. A CVE with a public Metasploit module keeps
    # having one, so the list accumulates.
    # See BaseFeed.full_list_kind for what each kind does.
    full_list_kind = FULL_LIST_CUMULATIVE
    default_sync_frequency = 86400

    async def fetch(self) -> str:
        """Fetch the feed, auto-detecting gzip encoding.

        Two-stage decode:
        1. Try gzip decompression (Content-Encoding or raw bytes).
        2. Fallback to raw UTF-8 decode if gzip fails.
        """
        response = await self._fetch_url(_FEED_URL)
        raw_bytes = response.content

        # Stage 1: try gzip decompression
        if response.headers.get("Content-Encoding", "").lower() == "gzip":
            try:
                return gzip.decompress(raw_bytes).decode("utf-8")
            except Exception:
                pass

        # Also try gzip even without header (response may be raw gzip bytes)
        try:
            return gzip.decompress(raw_bytes).decode("utf-8")
        except Exception:
            pass

        # Stage 2: fallback to raw UTF-8
        return raw_bytes.decode("utf-8", errors="replace")

    async def parse(self, raw: str) -> List[Dict[str, Any]]:
        """Parse one-CVE-per-line text into normalised IOC dicts."""
        seen: set[str] = set()
        iocs: List[Dict[str, Any]] = []

        for line in raw.splitlines():
            line = line.strip()
            if not line or line.startswith("#"):
                continue

            # Validate CVE format
            if not _CVE_RE.match(line):
                logger.debug("Skipping non-CVE line: %r", line[:80])
                continue

            cve_id = line.upper()

            dedup_key = f"cve:{cve_id}"
            if dedup_key in seen:
                continue
            seen.add(dedup_key)

            iocs.append(self._make_ioc(
                ioc_type="cve",
                value=cve_id,
                confidence=80,
                tags=list(_TAGS),
                metadata={
                    "source": "ecrimelabs-metasploit",
                    "exploit_framework": "metasploit",
                },
            ))

        logger.info("%s: parsed %d CVE(s)", self.name, len(iocs))
        return iocs
