"""AbuseIPDB feed connector — requires free API key."""

from datetime import datetime
from typing import Any, List, Dict, Optional

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
            import structlog
            structlog.get_logger().warning(
                "abuseipdb_feed_skipped",
                reason="no_api_key",
                hint="Set ABUSEIPDB_API_KEY environment variable.",
            )
            return {"data": []}

        response = await self._fetch_url(
            self.url,
            headers={
                "Key": self.api_key,
                "Accept": "application/json",
            },
            # confidenceMinimum=75 gives broader coverage; max limit = 10000
            params={"confidenceMinimum": 75, "limit": 10000},
        )
        return response.json()

    async def parse(self, raw_data: Any) -> List[Dict[str, Any]]:
        iocs = []
        data = raw_data.get("data", []) or []

        for entry in data:
            ip = (entry.get("ipAddress") or "").strip()
            if not ip:
                continue

            # Skip whitelisted IPs
            if entry.get("isWhitelisted"):
                continue

            abuse_score = int(entry.get("abuseConfidenceScore") or 0)
            # Map 0-100 confidence directly to threat score
            threat_score = min(100, max(30, abuse_score))

            # Parse last reported timestamp
            last_seen: Optional[datetime] = None
            raw_ts = entry.get("lastReportedAt")
            if raw_ts:
                try:
                    last_seen = datetime.fromisoformat(raw_ts.replace("Z", "+00:00")).replace(tzinfo=None)
                except ValueError:
                    pass

            tags = ["abuseipdb", "abuse"]
            domain = entry.get("domain")
            if domain:
                tags.append(f"domain:{domain}")

            iocs.append(self._make_ioc(
                ioc_type="ip",
                value=ip,
                tags=tags,
                threat_score=threat_score,
                confidence=abuse_score,
                last_seen=last_seen,
                metadata={
                    "abuse_confidence": abuse_score,
                    "total_reports": entry.get("totalReports"),
                    "num_distinct_users": entry.get("numDistinctUsers"),
                    "country_code": entry.get("countryCode"),
                    "usage_type": entry.get("usageType"),
                    "isp": entry.get("isp"),
                    "domain": domain,
                    "source": "abuseipdb",
                },
            ))

        return iocs
