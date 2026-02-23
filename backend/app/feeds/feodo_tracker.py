"""Feodo Tracker (abuse.ch) feed connector — free, no API key required."""

import csv
import io
from typing import Any, List, Dict

from app.feeds.base import BaseFeed


class FeodoTrackerFeed(BaseFeed):
    name = "Feodo Tracker"
    slug = "feodo-tracker"
    feed_type = "csv"
    url = "https://feodotracker.abuse.ch/downloads/ipblocklist_recommended.txt"
    description = "Feodo Tracker tracks botnet C2 infrastructure"
    requires_api_key = False
    default_sync_frequency = 1800

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
                tags=["feodo-tracker", "botnet", "c2"],
                threat_score=85,
                confidence=90,
                metadata={"source": "feodo-tracker", "threat_type": "botnet_c2"},
                mitre_techniques=["T1071", "T1573"],
            ))

        return iocs
