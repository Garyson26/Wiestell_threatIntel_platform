"""AbuseIPDB feed connector — requires free API key."""

from datetime import datetime
from typing import Any, List, Dict, Optional

from app.feeds.base import SHAPE_CURRENT_STATE_LIST, BaseFeed


class AbuseIPDBFeed(BaseFeed):
    name = "AbuseIPDB"
    slug = "abuseipdb"

    # The blacklist is "most-reported IPs in the last N days" -- entries drop off it,
    # so remaining on it is AbuseIPDB re-asserting the IP is still being reported. That
    # is a CURRENT-STATE list, and it carries timestamps as well, which is exactly the
    # combination the old two-attribute scheme could not express: declaring
    # `full_list_kind` implied timestamp-free, so this connector declared NOTHING and
    # got its behaviour by accident.
    source_shape = SHAPE_CURRENT_STATE_LIST
    feed_type = "api"
    url = "https://api.abuseipdb.com/api/v2/blacklist"
    description = "AbuseIPDB blacklist of reported malicious IPs"
    requires_api_key = True
    api_key_env = "ABUSEIPDB_API_KEY"
    default_sync_frequency = 86400

    async def fetch(self) -> Any:
        import structlog as _structlog
        _log = _structlog.get_logger()

        if not self.api_key:
            raise ValueError(
                "AbuseIPDB requires an API key. "
                "Register for free at https://www.abuseipdb.com/ and set ABUSEIPDB_API_KEY."
            )

        import httpx as _httpx
        try:
            response = await self._fetch_url(
                self.url,
                headers={
                    "Key": self.api_key,
                    "Accept": "application/json",
                },
                # confidenceMinimum=75 gives broader coverage; free tier allows up to 10 000
                params={"confidenceMinimum": 75, "limit": 10000},
            )
            return response.json()
        except _httpx.HTTPStatusError as exc:
            status = exc.response.status_code
            if status == 429:
                _log.warning(
                    "abuseipdb_rate_limited",
                    hint="AbuseIPDB rate limit hit; will retry on next scheduled sync.",
                )
            elif status in (401, 403):
                _log.warning(
                    "abuseipdb_auth_error",
                    status=status,
                    hint="Check ABUSEIPDB_API_KEY is valid.",
                )
            elif status == 402:
                _log.warning(
                    "abuseipdb_plan_limit",
                    status=status,
                    hint="AbuseIPDB plan limit reached; upgrade or reduce limit parameter.",
                )
            elif status == 422:
                _log.warning(
                    "abuseipdb_invalid_params",
                    status=status,
                    body=exc.response.text[:200],
                )
            else:
                _log.error("abuseipdb_http_error", status=status, error=str(exc))
            return {"data": []}

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
