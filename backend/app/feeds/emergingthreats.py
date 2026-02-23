"""Emerging Threats feed connector — free, no API key required."""

from typing import Any, List, Dict

from app.feeds.base import BaseFeed


class EmergingThreatsFeed(BaseFeed):
    name = "Emerging Threats"
    slug = "emerging-threats"
    feed_type = "csv"
    url = "https://rules.emergingthreats.net/blockrules/compromised-ips.txt"
    description = "Emerging Threats compromised IP blocklist"
    requires_api_key = False
    default_sync_frequency = 3600

    async def fetch(self) -> Any:
        response = await self._fetch_url(self.url)
        return response.text

    async def parse(self, raw_data: Any) -> List[Dict[str, Any]]:
        iocs = []
        for line in raw_data.strip().split("\n"):
            line = line.strip()
            if not line or line.startswith("#"):
                continue

            iocs.append(self._make_ioc(
                ioc_type="ip",
                value=line,
                tags=["emerging-threats", "compromised"],
                threat_score=60,
                confidence=65,
                metadata={"source": "emerging-threats"},
            ))

        return iocs
