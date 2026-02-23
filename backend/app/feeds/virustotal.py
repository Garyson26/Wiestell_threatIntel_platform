"""VirusTotal feed connector — requires free API key (4 req/min)."""

from typing import Any, List, Dict

from app.feeds.base import BaseFeed


class VirusTotalFeed(BaseFeed):
    name = "VirusTotal"
    slug = "virustotal"
    feed_type = "api"
    url = "https://www.virustotal.com/api/v3"
    description = "VirusTotal file and URL analysis"
    requires_api_key = True
    api_key_env = "VT_API_KEY"
    default_sync_frequency = 3600

    async def fetch(self) -> Any:
        # VT free tier is mainly for lookups, not bulk feed ingestion
        return {"data": []}

    async def parse(self, raw_data: Any) -> List[Dict[str, Any]]:
        return []
