"""AlienVault OTX feed connector — requires free API key."""

from typing import Any, List, Dict, Optional
from datetime import datetime, timezone

from app.feeds.base import BaseFeed


class OTXAlienVaultFeed(BaseFeed):
    name = "AlienVault OTX"
    slug = "otx-alienvault"
    feed_type = "api"
    url = "https://otx.alienvault.com/api/v1/pulses/subscribed"
    description = "AlienVault Open Threat Exchange - collaborative threat intelligence"
    requires_api_key = True
    api_key_env = "OTX_API_KEY"
    default_sync_frequency = 3600

    async def fetch(self) -> Any:
        if not self.api_key:
            return {"results": []}

        response = await self._fetch_url(
            self.url,
            headers={"X-OTX-API-KEY": self.api_key},
            params={"limit": 50, "modified_since": ""},
        )
        return response.json()

    async def parse(self, raw_data: Any) -> List[Dict[str, Any]]:
        iocs = []
        pulses = raw_data.get("results", [])

        for pulse in pulses:
            pulse_tags = [t.lower() for t in pulse.get("tags", []) if t]
            indicators = pulse.get("indicators", [])

            for indicator in indicators:
                ioc_type = self._map_type(indicator.get("type", ""))
                if not ioc_type:
                    continue

                value = indicator.get("indicator", "").strip()
                if not value:
                    continue

                tags = ["otx"] + pulse_tags
                iocs.append(self._make_ioc(
                    ioc_type=ioc_type,
                    value=value,
                    tags=tags,
                    confidence=65,
                    metadata={
                        "pulse_name": pulse.get("name"),
                        "pulse_id": pulse.get("id"),
                        "source": "otx-alienvault",
                    },
                ))

        return iocs

    @staticmethod
    def _map_type(raw_type: str) -> str:
        type_map = {
            "IPv4": "ip",
            "IPv6": "ip",
            "domain": "domain",
            "hostname": "domain",
            "URL": "url",
            "URI": "url",
            "FileHash-MD5": "hash",
            "FileHash-SHA1": "hash",
            "FileHash-SHA256": "hash",
            "email": "email",
            "CVE": "cve",
        }
        return type_map.get(raw_type, "")
