"""Blocklist.de feed connector — free, no API key required."""

from typing import Any, List, Dict

from app.feeds.base import BaseFeed, SHAPE_CURRENT_STATE_LIST


class BlocklistDeFeed(BaseFeed):
    name = "Blocklist.de"
    slug = "blocklist-de"
    feed_type = "csv"
    url = "https://lists.blocklist.de/lists/all.txt"
    description = "Blocklist.de collects IPs reported for attacks, spam, and abuse"
    requires_api_key = False
    # Whole list republished every sync, no per-record timestamps.
    # 23,112 IPs measured 2026-07-31. blocklist.de ages entries out, so remaining
    # on the list is a live re-assertion.
    # See BaseFeed.full_list_kind for what each kind does.
    source_shape = SHAPE_CURRENT_STATE_LIST
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
                tags=["blocklist-de", "abuse", "attack"],
                threat_score=55,
                confidence=60,
                metadata={"source": "blocklist-de"},
            ))

        return iocs
