"""VPN, Tor and relay enrichment for IP addresses via the VPNDetection API.

Says whether an IP IOC is a commercial VPN's exit, a Tor node or a privacy relay
(iCloud Private Relay, an enterprise web gateway), and on a paid key names the VPN
provider and adds the proxy and hosting flags. Registered only when
``VPNDETECTION_API_KEY`` is set, so no indicator is sent anywhere until the operator
opts in. A free key answers the VPN, Tor and relay flags with no daily or monthly cap.

It produces no risk signal: a VPN exit or a Tor node says how an attacker connects,
not that the indicator is malicious, so it is context for the analyst and leaves the
score alone. A flag missing from the answer is one the key's plan does not include,
stored as ``None``, never as ``False``.

Data provided by VPNDetection (https://vpndetection.io).
"""

from typing import Any, Dict, Optional

import structlog

from app.enrichers.base import BaseEnricher

logger = structlog.get_logger()

_API_URL = "https://api.vpndetection.io/"

_FLAGS = (
    "is_vpn", "is_tor", "is_relay",
    "is_resproxy", "is_dcproxy", "is_mobproxy", "is_pubproxy",
    "is_hosting", "is_anycast", "is_bogon",
)


def _flag(data: Dict[str, Any], key: str) -> Optional[bool]:
    value = data.get(key)
    return value if isinstance(value, bool) else None


class VPNDetectionEnricher(BaseEnricher):
    """VPN, Tor and relay flags for IP addresses (VPNDetection)."""

    name = "vpndetection"
    cache_ttl = 86400  # 24 hours: the datasets behind the flags rebuild daily

    def __init__(self, api_key: str) -> None:
        self.api_key = api_key

    def supports(self, ioc_type: str) -> bool:
        return ioc_type == "ip"

    async def enrich(self, value: str, ioc_type: str) -> Optional[Dict[str, Any]]:
        import httpx

        try:
            async with httpx.AsyncClient(
                timeout=5, headers={"Authorization": f"Bearer {self.api_key}"}
            ) as client:
                response = await client.get(f"{_API_URL}{value}")
        except Exception as e:
            # Never log the exception text, as the GeoIP enricher doesn't.
            logger.warning("vpndetection_lookup_failed", error=type(e).__name__)
            return {"error": "VPNDetection lookup failed", "assessed": []}

        if response.status_code == 401:
            logger.warning("vpndetection_key_rejected", status_code=401)
            return {"error": "VPNDetection rejected the API key", "assessed": []}

        if response.status_code == 400:
            # Not an address the API can parse: nothing to enrich, nothing to cache.
            return None

        if response.status_code != 200:
            logger.warning("vpndetection_http_error", status_code=response.status_code)
            return {"error": "VPNDetection lookup failed", "assessed": []}

        try:
            data = response.json()
        except Exception:
            logger.warning("vpndetection_invalid_response")
            return {"error": "VPNDetection returned an invalid response", "assessed": []}

        if not isinstance(data, dict):
            logger.warning("vpndetection_invalid_response")
            return {"error": "VPNDetection returned an invalid response", "assessed": []}

        result: Dict[str, Any] = {key: _flag(data, key) for key in _FLAGS}
        vpn = data.get("vpn")
        result["vpn_provider"] = vpn.get("provider_name") if isinstance(vpn, dict) else None
        result["assessed"] = []
        return result
