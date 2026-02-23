"""PhishTank feed connector — requires free API key."""

from typing import Any, List, Dict

from app.feeds.base import BaseFeed


class PhishTankFeed(BaseFeed):
    name = "PhishTank"
    slug = "phishtank"
    feed_type = "api"
    url = "http://data.phishtank.com/data/online-valid.json"
    description = "PhishTank verified phishing URLs"
    requires_api_key = False
    api_key_env = "PHISHTANK_API_KEY"
    default_sync_frequency = 3600

    async def fetch(self) -> Any:
        url = self.url
        if self.api_key:
            url = f"http://data.phishtank.com/data/{self.api_key}/online-valid.json"
        response = await self._fetch_url(url)
        return response.json()

    async def parse(self, raw_data: Any) -> List[Dict[str, Any]]:
        iocs = []
        if not isinstance(raw_data, list):
            return iocs

        for entry in raw_data[:500]:
            url = entry.get("url", "").strip()
            if not url:
                continue

            target = entry.get("target", "")
            tags = ["phishtank", "phishing"]
            if target:
                tags.append(f"target-{target.lower()}")

            iocs.append(self._make_ioc(
                ioc_type="url",
                value=url,
                tags=tags,
                threat_score=75,
                confidence=85,
                metadata={
                    "phish_id": entry.get("phish_id"),
                    "target": target,
                    "verified": entry.get("verified") == "yes",
                    "source": "phishtank",
                },
                mitre_techniques=["T1566"],
            ))

        return iocs
