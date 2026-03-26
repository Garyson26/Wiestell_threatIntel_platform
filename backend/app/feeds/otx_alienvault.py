"""AlienVault OTX feed connector — requires free API key."""

from typing import Any, List, Dict, Optional
from datetime import datetime, timezone, timedelta

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

        # Only fetch pulses modified in the last 7 days to keep syncs fast
        modified_since = (
            datetime.now(timezone.utc) - timedelta(days=7)
        ).strftime("%Y-%m-%dT%H:%M:%S.%f")

        all_pulses = []
        next_url: Optional[str] = self.url

        while next_url:
            response = await self._fetch_url(
                next_url,
                headers={"X-OTX-API-KEY": self.api_key},
                params={"limit": 100, "modified_since": modified_since} if next_url == self.url else {},
            )
            data = response.json()
            all_pulses.extend(data.get("results", []))

            # OTX paginates via a "next" URL in the response
            next_url = data.get("next")

        return {"results": all_pulses}

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
