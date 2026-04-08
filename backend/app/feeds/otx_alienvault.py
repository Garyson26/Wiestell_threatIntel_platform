"""AlienVault OTX (LevelBlue) DirectConnect feed connector."""

from datetime import datetime, timezone, timedelta
from typing import Any, Dict, List, Optional

import structlog

from app.feeds.base import BaseFeed

logger = structlog.get_logger()

# OTX API — confirmed from official documentation
# Auth: X-OTX-API-KEY header
# Pagination: follow "next" URL field in each response
# Indicator fields: indicator, type, created, is_active, expiration, description, title
# Pulse fields: id, name, tags, adversary, malware_families, attack_ids, TLP

# Safety cap on pagination — 100 pages × 100 results = 10,000 pulses max per sync.
# Without this, a bug in OTX's next URL could loop forever.
_MAX_PAGES = 100

# OTX timestamp formats seen in real responses (no timezone suffix — treat as UTC)
_TS_FORMATS = [
    "%Y-%m-%dT%H:%M:%S.%f",   # "2017-04-10T16:08:17.604000"
    "%Y-%m-%dT%H:%M:%S",       # "2017-04-10T16:08:19"
    "%Y-%m-%dT%H:%M:%SZ",      # "2023-09-07T00:00:00Z" (occasional variant)
]


class OTXAlienVaultFeed(BaseFeed):
    name = "AlienVault OTX"
    slug = "otx-alienvault"
    feed_type = "api"
    url = "https://otx.alienvault.com/api/v1/pulses/subscribed"
    description = "AlienVault Open Threat Exchange — collaborative threat intelligence"
    requires_api_key = True
    api_key_env = "OTX_API_KEY"
    default_sync_frequency = 3600

    # ── fetch ────────────────────────────────────────────────────────────────

    async def fetch(self) -> Dict[str, Any]:
        if not self.api_key:
            raise ValueError(
                "OTX AlienVault requires a free API key. "
                "Register at https://otx.alienvault.com and set OTX_API_KEY."
            )
        masked = self.api_key[:4] + "****" if len(self.api_key) > 4 else "****"
        logger.info("otx_fetch_start", api_key=masked)

        # Only fetch pulses modified in the last 7 days to keep syncs fast.
        # OTX docs confirm "modified_since" filters on pulse modification date.
        modified_since = (
            datetime.now(timezone.utc) - timedelta(days=7)
        ).strftime("%Y-%m-%dT%H:%M:%S.%f")

        all_pulses: List[Dict] = []
        next_url: Optional[str] = self.url
        page = 0

        while next_url and page < _MAX_PAGES:
            page += 1
            try:
                # First page: pass modified_since + limit as query params.
                # Subsequent pages: next_url already contains all params embedded
                #   in the URL itself (e.g. ?modified_since=...&limit=100&page=2).
                #   Do NOT pass extra params — they would duplicate or override the
                #   pagination params already in the URL.
                if page == 1:
                    resp = await self.client.get(
                        next_url,
                        headers={"X-OTX-API-KEY": self.api_key},
                        params={"limit": 100, "modified_since": modified_since},
                    )
                else:
                    resp = await self.client.get(
                        next_url,
                        headers={"X-OTX-API-KEY": self.api_key},
                    )
                resp.raise_for_status()
                data = resp.json()
                batch = data.get("results", [])
                all_pulses.extend(batch)
                next_url = data.get("next")  # null when on last page
                logger.info("otx_page_fetched", page=page, batch_size=len(batch))

            except Exception as exc:
                logger.warning("otx_fetch_page_failed", page=page, error=str(exc))
                break

        logger.info("otx_fetch_complete", total_pulses=len(all_pulses), pages=page)
        return {"results": all_pulses}

    # ── parse ────────────────────────────────────────────────────────────────

    async def parse(self, raw_data: Dict[str, Any]) -> List[Dict[str, Any]]:
        iocs: List[Dict[str, Any]] = []
        # Deduplicate by ioc_type:value — same IOC from multiple pulses = one entry.
        # OTX noise means the same IP/domain appears in dozens of pulses.
        seen: set = set()

        pulses = raw_data.get("results", [])
        for pulse in pulses:
            try:
                pulse_iocs = self._parse_pulse(pulse, seen)
                iocs.extend(pulse_iocs)
            except Exception as exc:
                logger.warning("otx_pulse_parse_failed",
                               pulse_id=pulse.get("id"), error=str(exc))
                continue

        logger.info("otx_parse_complete", total_iocs=len(iocs))
        return iocs

    # ── pulse parser ─────────────────────────────────────────────────────────

    def _parse_pulse(
        self, pulse: Dict[str, Any], seen: set
    ) -> List[Dict[str, Any]]:
        """
        Parse one OTX pulse and return IOCs for all its active, non-expired
        indicators.

        Key fields extracted:
          Pulse: name, id, tags, adversary, malware_families, attack_ids, TLP
          Indicator: indicator, type, created, is_active, expiration
        """
        # ── Pulse-level context ──────────────────────────────────────────────
        pulse_name    = (pulse.get("name") or "").strip()
        pulse_id      = pulse.get("id", "")
        pulse_tlp     = (pulse.get("TLP") or pulse.get("tlp") or "white").lower()
        adversary     = (pulse.get("adversary") or "").strip()

        # Build pulse-level tags
        pulse_tags: List[str] = ["otx"]
        for t in pulse.get("tags") or []:
            if t:
                pulse_tags.append(str(t).lower())

        # Extract malware family names — field can be list of strings or list of
        # objects with "display_name". Handle both formats seen in the wild.
        for mf in pulse.get("malware_families") or []:
            if isinstance(mf, str) and mf:
                pulse_tags.append(mf.lower().replace(" ", "-"))
            elif isinstance(mf, dict):
                name = mf.get("display_name") or mf.get("name") or ""
                if name:
                    pulse_tags.append(name.lower().replace(" ", "-"))

        # Extract MITRE ATT&CK technique IDs from attack_ids.
        # Format confirmed from official schema:
        # [{"id": "T1059", "name": "...", "display_name": "T1059: ..."}]
        mitre_techniques: List[str] = []
        for atk in pulse.get("attack_ids") or []:
            if isinstance(atk, dict):
                tid = atk.get("id") or atk.get("display_name") or ""
                if tid:
                    mitre_techniques.append(str(tid))
            elif isinstance(atk, str) and atk:
                mitre_techniques.append(atk)

        # Build pulse metadata — stored on each IOC
        pulse_meta: Dict[str, Any] = {
            "pulse_name":   pulse_name,
            "pulse_id":     pulse_id,
            "pulse_tlp":    pulse_tlp,
            "source":       "otx-alienvault",
        }
        if adversary:
            pulse_meta["adversary"] = adversary

        # ── Indicators ───────────────────────────────────────────────────────
        iocs = []
        for indicator in pulse.get("indicators") or []:
            try:
                ioc = self._parse_indicator(
                    indicator, pulse_tags, pulse_meta, mitre_techniques, seen
                )
                if ioc:
                    iocs.append(ioc)
            except Exception:
                continue
        return iocs

    def _parse_indicator(
        self,
        indicator: Dict[str, Any],
        pulse_tags: List[str],
        pulse_meta: Dict[str, Any],
        mitre_techniques: List[str],
        seen: set,
    ) -> Optional[Dict[str, Any]]:
        """
        Parse one indicator from a pulse.

        Filters applied (confirmed from official OTX Python SDK tests):
          - is_active == 0  → skip (indicator has been deactivated)
          - expiration != null AND expiration < now()  → skip (expired)
        """
        # ── Active / expiry check ────────────────────────────────────────────
        # is_active: 1 = active, 0 = inactive. Can be int or string "1"/"0".
        is_active = indicator.get("is_active", 1)
        if str(is_active) == "0":
            return None

        expiration_str = indicator.get("expiration")
        if expiration_str:
            exp = _parse_ts(expiration_str)
            if exp and exp < datetime.now(timezone.utc):
                return None  # indicator has expired

        # ── IOC value and type ───────────────────────────────────────────────
        value = (indicator.get("indicator") or "").strip()
        if not value:
            return None

        ioc_type = self._map_type(indicator.get("type", ""))
        if not ioc_type:
            return None  # unsupported type — skip silently

        # ── Deduplication ────────────────────────────────────────────────────
        dedup_key = f"{ioc_type}:{value.lower()}"
        if dedup_key in seen:
            return None
        seen.add(dedup_key)

        # ── Timestamp ────────────────────────────────────────────────────────
        # Indicator "created" format: "2017-04-10T16:08:19" — no timezone suffix.
        first_seen = _parse_ts(indicator.get("created"))

        # ── Tags ─────────────────────────────────────────────────────────────
        # Include indicator-level description as a tag if meaningful
        tags = list(pulse_tags)  # copy — don't mutate the pulse-level list
        ind_title = (indicator.get("title") or "").strip()
        if ind_title and len(ind_title) < 60:  # skip very long descriptions
            tags.append(ind_title.lower())

        return self._make_ioc(
            ioc_type=ioc_type,
            value=value,
            tags=list(dict.fromkeys(tags)),      # deduplicate tags, preserve order
            threat_score=None,
            confidence=65,                        # OTX is community-submitted — moderate confidence
            metadata=pulse_meta,
            mitre_techniques=mitre_techniques,
            first_seen=first_seen,
        )

    # ── type mapping ─────────────────────────────────────────────────────────

    @staticmethod
    def _map_type(raw_type: str) -> str:
        return {
            # Network indicators
            "IPv4":            "ip",
            "IPv6":            "ip",
            "CIDR":            "ip",
            # Domain/host
            "domain":          "domain",
            "hostname":        "domain",
            # URL
            "URL":             "url",
            "URI":             "url",
            # File hashes
            "FileHash-MD5":    "hash",
            "FileHash-SHA1":   "hash",
            "FileHash-SHA256": "hash",
            "FileHash-PEHASH": "hash",
            "FileHash-IMPHASH":"hash",
            # Email
            "email":           "email",
            # Vulnerability
            "CVE":             "cve",
        }.get(raw_type, "")


# ── module-level helpers ─────────────────────────────────────────────────────

def _parse_ts(value: Optional[str]) -> Optional[datetime]:
    """
    Parse an OTX timestamp string to a timezone-aware UTC datetime.

    Formats seen in real OTX responses (no timezone suffix — treated as UTC):
      "2017-04-10T16:08:17.604000"   — pulse created/modified
      "2017-04-10T16:08:19"          — indicator created
      "2023-09-07T00:00:00"          — indicator expiration
      "2023-09-07T00:00:00Z"         — occasional Z suffix variant
    """
    if not value:
        return None
    clean = value.strip().rstrip("Z")  # strip trailing Z if present
    for fmt in _TS_FORMATS:
        try:
            return datetime.strptime(clean, fmt).replace(tzinfo=timezone.utc)
        except (ValueError, AttributeError):
            continue
    return None
