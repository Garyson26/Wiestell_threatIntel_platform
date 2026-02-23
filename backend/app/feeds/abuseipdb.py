"""AbuseIPDB feed connector — requires free API key (1000 checks/day)."""

from typing import Any, List, Dict

from app.feeds.base import BaseFeed


class AbuseIPDBFeed(BaseFeed):
    name = "AbuseIPDB"
    slug = "abuseipdb"
    feed_type = "api"
    url = "https://api.abuseipdb.com/api/v2/blacklist"
    description = "AbuseIPDB blacklist of reported malicious IPs"
    requires_api_key = True
    api_key_env = "ABUSEIPDB_API_KEY"
    default_sync_frequency = 86400

    async def fetch(self) -> Any:
        if not self.api_key:
            return {"data": []}

        response = await self._fetch_url(
            self.url,
            headers={
                "Key": self.api_key,
                "Accept": "application/json",
            },
            params={"confidenceMinimum": 90, "limit": 500},
        )
        return response.json()

    async def parse(self, raw_data: Any) -> List[Dict[str, Any]]:
        iocs = []
        data = raw_data.get("data", [])

        for entry in data:
            ip = entry.get("ipAddress", "").strip()
            if not ip:
                continue

            abuse_score = entry.get("abuseConfidenceScore", 0)
            score = min(100, int(abuse_score * 0.9))

            iocs.append(self._make_ioc(
                ioc_type="ip",
                value=ip,
                tags=["abuseipdb", "abuse"],
                threat_score=score,
                confidence=abuse_score,
                metadata={
                    "abuse_confidence": abuse_score,
                    "country_code": entry.get("countryCode"),
                    "source": "abuseipdb",
                },
            ))

        return iocs
