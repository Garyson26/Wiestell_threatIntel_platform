"""ThreatFox (abuse.ch) feed connector — free, no API key required."""

from typing import Any, List, Dict
from datetime import datetime, timezone

from app.feeds.base import BaseFeed


class ThreatFoxFeed(BaseFeed):
    name = "ThreatFox"
    slug = "threatfox"
    feed_type = "api"
    url = "https://threatfox-api.abuse.ch/api/v1/"
    description = "ThreatFox shares IOCs associated with malware"
    requires_api_key = False
    default_sync_frequency = 1800

    async def fetch(self) -> Any:
        response = await self.client.post(
            self.url,
            json={"query": "get_iocs", "days": 1},
        )
        response.raise_for_status()
        return response.json()

    async def parse(self, raw_data: Any) -> List[Dict[str, Any]]:
        iocs = []
        data = raw_data.get("data", [])
        if not data:
            return iocs

        for entry in data:
            try:
                ioc_value = entry.get("ioc", "").strip()
                ioc_type_raw = entry.get("ioc_type", "")
                threat_type = entry.get("threat_type", "")
                malware = entry.get("malware_printable", "")
                confidence_level = entry.get("confidence_level", 50)
                tags_raw = entry.get("tags") or []

                if not ioc_value:
                    continue

                ioc_type = self._map_type(ioc_type_raw)
                if not ioc_type:
                    continue

                # Handle ip:port format
                if ioc_type == "ip" and ":" in ioc_value:
                    ioc_value = ioc_value.split(":")[0]

                tags = ["threatfox"]
                if malware:
                    tags.append(malware.lower().replace(" ", "-"))
                if threat_type:
                    tags.append(threat_type.lower())
                if tags_raw:
                    tags.extend([str(t).lower() for t in tags_raw if t])

                mitre = []
                malpedia = entry.get("malware_malpedia")
                if malpedia:
                    tags.append("malpedia")

                first_seen = None
                if entry.get("first_seen_utc"):
                    try:
                        first_seen = datetime.strptime(
                            entry["first_seen_utc"], "%Y-%m-%d %H:%M:%S UTC"
                        ).replace(tzinfo=timezone.utc)
                    except (ValueError, TypeError):
                        pass

                iocs.append(self._make_ioc(
                    ioc_type=ioc_type,
                    value=ioc_value,
                    tags=tags,
                    threat_score=None,
                    confidence=min(int(confidence_level), 100),
                    metadata={
                        "malware": malware,
                        "threat_type": threat_type,
                        "reporter": entry.get("reporter"),
                        "source": "threatfox",
                    },
                    mitre_techniques=mitre,
                    first_seen=first_seen,
                ))
            except Exception:
                continue

        return iocs

    @staticmethod
    def _map_type(raw_type: str) -> str:
        type_map = {
            "ip:port": "ip",
            "domain": "domain",
            "url": "url",
            "md5_hash": "hash",
            "sha256_hash": "hash",
            "sha1_hash": "hash",
        }
        return type_map.get(raw_type, "")
