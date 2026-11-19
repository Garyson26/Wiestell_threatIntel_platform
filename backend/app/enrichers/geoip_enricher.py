"""GeoIP enrichment via the IP2Location.io API.

The MaxMind GeoLite2 database this used to read was downloaded at build time and
failed open, so a deploy without MaxMind credentials silently lost country and ASN
for every IP. The API works keyless (1,000 requests/day), so this source is always
available; ``IP2LOCATION_IO_KEY`` raises the allowance to 50,000/month.

Data provided by IP2Location.io (https://www.ip2location.io).
"""

import logging
from typing import Any, Dict, Optional

import structlog

from app.config import settings
from app.enrichers.base import BaseEnricher

logger = structlog.get_logger()

_API_URL = "https://api.ip2location.io/"


class _RedactKeyFromHttpxLogs(logging.Filter):
    """Strip the API key from httpx's request log line.

    The key travels as a URL parameter, and httpx logs the full URL at INFO.
    """

    def filter(self, record: logging.LogRecord) -> bool:
        key = settings.IP2LOCATION_IO_KEY
        if key:
            message = record.getMessage()
            if key in message:
                record.msg = message.replace(key, "***")
                record.args = ()
        return True


logging.getLogger("httpx").addFilter(_RedactKeyFromHttpxLogs())


def _text(value: Any) -> Optional[str]:
    """Normalise a string field; the API sends ``-`` for some unknowns."""
    if not isinstance(value, str):
        return None
    value = value.strip()
    return value if value and value != "-" else None


class GeoIPEnricher(BaseEnricher):
    """Country, city and ASN lookup for IP addresses (IP2Location.io)."""

    name = "geoip"

    @property
    def cache_ttl(self) -> int:
        return settings.CACHE_TTL_GEOIP

    def supports(self, ioc_type: str) -> bool:
        return ioc_type == "ip"

    async def enrich(self, value: str, ioc_type: str) -> Optional[Dict[str, Any]]:
        import httpx

        result: Dict[str, Any] = {
            "country": None, "country_code": None,
            "city": None, "latitude": None, "longitude": None,
            "asn": None, "asn_org": None, "is_proxy": None,
            "assessed": [],
        }

        params = {"ip": value, "format": "json"}
        if settings.IP2LOCATION_IO_KEY:
            params["key"] = settings.IP2LOCATION_IO_KEY

        try:
            async with httpx.AsyncClient(timeout=5) as client:
                response = await client.get(_API_URL, params=params)
        except Exception as e:
            # Never log the exception text: an HTTP error can echo the request URL,
            # which carries the API key.
            logger.warning("ip2location_io_lookup_failed", error=type(e).__name__)
            result["error"] = "IP2Location.io lookup failed"
            return result

        if response.status_code == 401:
            # Keyless daily allowance, keyed monthly quota, and an invalid key all
            # return 401 / error 10000. Quota exhaustion is routine, not a crash.
            logger.warning("ip2location_io_quota_exhausted", status_code=401)
            result["error"] = "IP2Location.io quota exhausted or key rejected"
            return result

        if response.status_code != 200:
            logger.warning("ip2location_io_http_error", status_code=response.status_code)
            result["error"] = "IP2Location.io lookup failed"
            return result

        try:
            data = response.json()
        except Exception:
            logger.warning("ip2location_io_invalid_response")
            result["error"] = "IP2Location.io returned an invalid response"
            return result

        if not isinstance(data, dict) or data.get("error"):
            logger.warning("ip2location_io_api_error")
            result["error"] = "IP2Location.io lookup failed"
            return result

        result.update({
            "country": _text(data.get("country_name")),
            "country_code": _text(data.get("country_code")),
            "city": _text(data.get("city_name")),
            "latitude": data.get("latitude"),
            "longitude": data.get("longitude"),
            "asn": data.get("asn"),
            "asn_org": _text(data.get("as")),
            "is_proxy": data.get("is_proxy"),
        })

        # Only a resolved country makes `high_risk_country` assessable. A failed or
        # empty lookup is silence, not a low-risk country.
        result["assessed"] = ["high_risk_country"] if result["country_code"] else []
        return result
