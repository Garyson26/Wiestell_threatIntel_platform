"""VirusTotal feed connector — requires API key.

Note: Bulk threat intelligence feeds (e.g. /api/v3/feeds/) are VT Premium-only.
The free tier only supports individual IOC lookups, which are handled by the
enrichment engine (reputation_enricher.py), not this feed connector.

This connector will return 0 IOCs unless a premium-tier key is configured.
"""

from typing import Any, List, Dict

import structlog
from app.feeds.base import BaseFeed

logger = structlog.get_logger()


class VirusTotalFeed(BaseFeed):
    name = "VirusTotal"
    slug = "virustotal"
    feed_type = "api"
    url = "https://www.virustotal.com/api/v3"
    description = "VirusTotal file and URL analysis (bulk feeds require Premium tier)"
    requires_api_key = True
    api_key_env = "VT_API_KEY"
    default_sync_frequency = 3600

    async def fetch(self) -> Any:
        if not self.api_key:
            logger.info("virustotal_feed_skipped", reason="no_api_key")
            return {"data": []}

        # Attempt premium feed endpoint; gracefully skip on 403 (non-premium key)
        try:
            response = await self.client.get(
                f"{self.url}/feeds/files",
                headers={"x-apikey": self.api_key},
                params={"cursor": ""},
            )
            if response.status_code == 403:
                logger.warning(
                    "virustotal_feed_unavailable",
                    reason="premium_required",
                    hint="Bulk feeds require a VirusTotal Premium subscription. "
                         "Individual IOC lookups still work via the enrichment engine.",
                )
                return {"data": []}
            response.raise_for_status()
            return response.json()
        except Exception as e:
            logger.error("virustotal_feed_error", error=str(e))
            return {"data": []}

    async def parse(self, raw_data: Any) -> List[Dict[str, Any]]:
        # Premium feed returns NDJSON file objects; parse if present
        items = raw_data.get("data", [])
        if not items:
            return []

        iocs = []
        for item in items:
            attributes = item.get("attributes", {})
            sha256 = attributes.get("sha256", "").strip()
            if not sha256:
                continue
            last_analysis = attributes.get("last_analysis_stats", {})
            malicious = last_analysis.get("malicious", 0)
            total = sum(last_analysis.values()) or 1
            score = min(100, int((malicious / total) * 100))
            iocs.append(self._make_ioc(
                ioc_type="hash",
                value=sha256,
                tags=["virustotal", "malware"],
                threat_score=score,
                confidence=min(100, malicious * 5),
                metadata={"source": "virustotal", "malicious_engines": malicious},
            ))
        return iocs
