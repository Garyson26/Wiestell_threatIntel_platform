"""Emerging Threats feed connector — free, no API key required."""

from typing import Any, List, Dict

from app.feeds.base import FULL_LIST_CURRENT_STATE, BaseFeed

# Emerging Threats publishes several complementary blocklists
_ET_FEEDS = [
    {
        "url": "https://rules.emergingthreats.net/blockrules/compromised-ips.txt",
        "tags": ["emerging-threats", "compromised"],
        "threat_score": 60,
    },
    {
        "url": "https://rules.emergingthreats.net/fwrules/emerging-Block-IPs.txt",
        "tags": ["emerging-threats", "block"],
        "threat_score": 65,
    },
]


class EmergingThreatsFeed(BaseFeed):
    name = "Emerging Threats"
    slug = "emerging-threats"
    feed_type = "csv"
    url = "https://rules.emergingthreats.net/blockrules/compromised-ips.txt"
    description = "Emerging Threats compromised IP and block IP lists"
    requires_api_key = False
    # Whole list republished every sync, no per-record timestamps.
    # 586 compromised IPs measured 2026-07-31. The list is current-state — entries
    # drop off when no longer seen compromised.
    # See BaseFeed.full_list_kind for what each kind does.
    full_list_kind = FULL_LIST_CURRENT_STATE
    default_sync_frequency = 3600

    async def fetch(self) -> Any:
        results = []
        for feed_def in _ET_FEEDS:
            try:
                response = await self._fetch_url(feed_def["url"])
                results.append({
                    "text": response.text,
                    "tags": feed_def["tags"],
                    "threat_score": feed_def["threat_score"],
                })
            except Exception:
                # If one list fails, continue with others
                pass
        return results

    async def parse(self, raw_data: Any) -> List[Dict[str, Any]]:
        iocs = []
        for feed_result in raw_data:
            text = feed_result["text"]
            tags = feed_result["tags"]
            threat_score = feed_result["threat_score"]
            for line in text.strip().split("\n"):
                line = line.strip()
                if not line or line.startswith("#"):
                    continue
                iocs.append(self._make_ioc(
                    ioc_type="ip",
                    value=line,
                    tags=tags,
                    threat_score=threat_score,
                    confidence=65,
                    metadata={"source": "emerging-threats"},
                ))
        return iocs
