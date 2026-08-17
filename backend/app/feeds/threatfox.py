"""ThreatFox (abuse.ch) feed connector — API + free bulk exports."""

import csv
import io
from datetime import datetime, timezone, timedelta
from typing import Any, Dict, List, Optional, Tuple

import structlog

from app.feeds.base import BaseFeed, SHAPE_SLIDING_WINDOW
from app.utils.sanitize import redact_secrets

logger = structlog.get_logger()

# ThreatFox expires IOCs older than 6 months (policy enforced since 2025-05-01).
# Validated live: https://threatfox.abuse.ch/export/ — "Since 2025-05-01, we are
# expiring IOCs that are older than 6 months."
_MAX_IOC_AGE_DAYS = 180

# ThreatFox export CSV column order — header line is commented out in the file,
# so we define fieldnames manually to avoid parsing the `# "first_seen_utc"` line.
_CSV_FIELDNAMES = [
    "first_seen_utc", "ioc_id", "ioc_value", "ioc_type", "threat_type",
    "fk_malware", "malware_alias", "malware_printable", "last_seen_utc",
    "confidence_level", "is_compromised", "reference", "tags", "anonymous",
    "reporter",
]


class ThreatFoxFeed(BaseFeed):
    name = "ThreatFox"
    slug = "threatfox"
    feed_type = "api"
    url = "https://threatfox-api.abuse.ch/api/v1/"
    description = "ThreatFox shares IOCs associated with malware families"
    requires_api_key = False  # Optional - works without key but limited features
    api_key_env = "THREATFOX_API_KEY"
    source_shape = SHAPE_SLIDING_WINDOW

    # MEASURED 2026-07-30 across all four CSV exports: 2,486 IOCs spanning
    #   2026-02-04 00:02:27Z .. 2026-07-30 13:05:05Z  =  176d 13h  (4237.04 hours)
    #
    # Two things that measurement corrected. First, the endpoints are named
    # ".../recent/" but return essentially the whole non-expired catalogue, not a
    # short window. Second, 176.5 days is just under the 180-day expiry
    # (_MAX_IOC_AGE_DAYS) — so the lower bound is set by ThreatFox's *expiry
    # policy*, not by a "recent" cutoff.
    #
    # Consequence, stated plainly: with a ~706x margin against a 6-hour interval,
    # the continuity check will effectively never fire for this feed. It is retained
    # because it is cheap, cannot raise, and would catch abuse.ch narrowing the
    # export — not because this feed is at risk today.
    _MEASURED_WINDOW_HOURS = 4237.04
    default_sync_frequency = 1800

    # ── Free export endpoints — no auth, validated live April 2026 ──────────
    _EXPORT_SHA256  = "https://threatfox.abuse.ch/export/csv/sha256/recent/"
    _EXPORT_MD5     = "https://threatfox.abuse.ch/export/csv/md5/recent/"
    _EXPORT_URLS    = "https://threatfox.abuse.ch/export/csv/urls/recent/"
    _EXPORT_IP_PORT = "https://threatfox.abuse.ch/export/csv/ip-port/recent/"   # ← was missing
    _HOSTFILE       = "https://threatfox.abuse.ch/downloads/hostfile/"
    # Note: https://threatfox.abuse.ch/export/csv/recent/ returns ALL types
    # in one feed — useful if you want to simplify to a single endpoint later.

    # ── fetch ────────────────────────────────────────────────────────────────

    async def fetch(self) -> Dict[str, Any]:
        if self.api_key:
            masked = self.api_key[:4] + "****" if len(self.api_key) > 4 else "****"
            logger.info("threatfox_fetch_start", api_key=masked)
        else:
            logger.info("threatfox_fetch_start", api_key="none", note="Using free endpoints only")

        results: Dict[str, Any] = {}

        # 1. Query API — Auth-Key in request HEADER (not URL) - optional
        if self.api_key:
            try:
                resp = await self.client.post(
                    self.url,
                    headers={"Auth-Key": self.api_key},
                    json={"query": "get_iocs", "days": 1},
                )
                resp.raise_for_status()
                results["api"] = resp.json()
                logger.info("threatfox_api_fetched")
            except Exception as exc:
                logger.warning("threatfox_api_failed", error=redact_secrets(exc))
                results["api"] = {}
        else:
            # API works without auth for basic queries
            try:
                resp = await self.client.post(
                    self.url,
                    json={"query": "get_iocs", "days": 1},
                )
                resp.raise_for_status()
                results["api"] = resp.json()
                logger.info("threatfox_api_fetched", auth="none")
            except Exception as exc:
                logger.warning("threatfox_api_failed_no_auth", error=redact_secrets(exc))
                results["api"] = {}

        # 2–5. Free CSV exports — no auth required
        for key, endpoint in (
            ("sha256_csv",  self._EXPORT_SHA256),
            ("md5_csv",     self._EXPORT_MD5),
            ("url_csv",     self._EXPORT_URLS),
            ("ip_port_csv", self._EXPORT_IP_PORT),   # ← was missing
        ):
            try:
                resp = await self.client.get(endpoint)
                resp.raise_for_status()
                results[key] = resp.text
                logger.info("threatfox_export_fetched", source=key)
            except Exception as exc:
                logger.warning("threatfox_export_failed", source=key, error=redact_secrets(exc))
                results[key] = ""

        # 6. Hostfile — DNS domains, no auth required
        try:
            resp = await self.client.get(self._HOSTFILE)
            resp.raise_for_status()
            results["hostfile"] = resp.text
            logger.info("threatfox_hostfile_fetched")
        except Exception as exc:
            logger.warning("threatfox_hostfile_failed", error=redact_secrets(exc))
            results["hostfile"] = ""

        return results

    # ── parse ────────────────────────────────────────────────────────────────

    async def parse(self, raw_data: Dict[str, Any]) -> List[Dict[str, Any]]:
        iocs: List[Dict[str, Any]] = []
        seen: set = set()   # deduplicates across all six sources

        iocs.extend(self._parse_api(raw_data.get("api", {}), seen))

        # Every export is a slice of the same rolling window, so accumulate
        # timestamps across all of them and record the union once.
        window_timestamps: List[Optional[datetime]] = []
        for key in ("sha256_csv", "md5_csv", "url_csv", "ip_port_csv"):   # ← added ip_port_csv
            csv_text = raw_data.get(key, "")
            if csv_text:
                iocs.extend(self._parse_export_csv(
                    csv_text, seen, window_timestamps=window_timestamps
                ))
        self.record_observed_window(window_timestamps)

        hostfile_text = raw_data.get("hostfile", "")
        if hostfile_text:
            iocs.extend(self._parse_hostfile(hostfile_text, seen))

        logger.info("threatfox_parse_complete", total_iocs=len(iocs))
        return iocs

    # ── source-specific parsers ──────────────────────────────────────────────

    def _parse_api(
        self, raw: Dict[str, Any], seen: set
    ) -> List[Dict[str, Any]]:
        """Parse the JSON response from the API query endpoint."""
        iocs = []
        for entry in raw.get("data") or []:
            try:
                ioc_value = (entry.get("ioc") or "").strip()
                ioc_type_raw = entry.get("ioc_type", "")
                if not ioc_value:
                    continue

                ioc_type = self._map_type(ioc_type_raw)
                if not ioc_type:
                    continue

                # Strip port, preserve it in metadata
                ioc_value, port = self._split_ip_port(ioc_type, ioc_value)

                # API JSON uses "first_seen", CSV exports use "first_seen_utc" — try both
                first_seen = _parse_datetime(
                    entry.get("first_seen_utc") or entry.get("first_seen")
                )
                if _is_expired(first_seen):
                    continue

                dedup_key = f"{ioc_type}:{ioc_value}"
                if dedup_key in seen:
                    continue
                seen.add(dedup_key)

                malware    = entry.get("malware_printable", "") or ""
                threat_type = entry.get("threat_type", "") or ""
                tags_raw   = entry.get("tags") or []
                confidence = min(int(entry.get("confidence_level") or 50), 100)

                metadata: Dict[str, Any] = {
                    "malware":     malware,
                    "threat_type": threat_type,
                    "reporter":    entry.get("reporter"),
                    "source":      "threatfox_api",
                }
                if port is not None:
                    metadata["port"] = port
                if entry.get("malware_malpedia"):
                    metadata["malpedia_url"] = entry["malware_malpedia"]
                if entry.get("reference") and entry["reference"] != "None":
                    metadata["reference"] = entry["reference"]

                iocs.append(self._make_ioc(
                    ioc_type=ioc_type,
                    value=ioc_value,
                    tags=_build_tags(malware, threat_type, tags_raw),
                    threat_score=None,
                    confidence=confidence,
                    metadata=metadata,
                    mitre_techniques=[],
                    first_seen=first_seen,
                ))
            except Exception:
                continue
        return iocs

    def _parse_export_csv(
        self,
        raw_text: str,
        seen: set,
        window_timestamps: Optional[List[Optional[datetime]]] = None,
    ) -> List[Dict[str, Any]]:
        """
        Parse ThreatFox bulk export CSV files (sha256, md5, url exports).

        The export format has:
          - A block of `#` comment lines at the top (including the header as a comment).
          - Data rows that are NOT prefixed with `#`.
          - Column order matches _CSV_FIELDNAMES exactly.
        """
        data_lines = [
            line for line in raw_text.splitlines()
            if line.strip() and not line.startswith("#")
        ]
        if not data_lines:
            return []

        iocs = []
        reader = csv.DictReader(
            io.StringIO("\n".join(data_lines)),
            fieldnames=_CSV_FIELDNAMES,
            quotechar='"',
            skipinitialspace=True,
        )

        for row in reader:
            try:
                ioc_value = (row.get("ioc_value") or "").strip()
                ioc_type_raw = (row.get("ioc_type") or "").strip()
                if not ioc_value:
                    continue

                ioc_type = self._map_type(ioc_type_raw)
                if not ioc_type:
                    continue

                ioc_value, port = self._split_ip_port(ioc_type, ioc_value)

                first_seen = _parse_datetime(row.get("first_seen_utc"))
                if _is_expired(first_seen):
                    # Recorded *after* the expiry filter on purpose: a record we
                    # deliberately excluded for age was not lost to a sync gap, so
                    # counting it would mask real discontinuities behind the
                    # 180-day cutoff.
                    continue
                if window_timestamps is not None:
                    window_timestamps.append(first_seen)

                dedup_key = f"{ioc_type}:{ioc_value}"
                if dedup_key in seen:
                    continue
                seen.add(dedup_key)

                malware     = (row.get("malware_printable") or "").strip()
                threat_type = (row.get("threat_type") or "").strip()
                confidence  = min(int(row.get("confidence_level") or 50), 100)

                # Tags field is comma-separated inside the CSV cell
                tags_raw_str = (row.get("tags") or "").strip()
                tags_raw = (
                    [t.strip() for t in tags_raw_str.split(",") if t.strip()]
                    if tags_raw_str else []
                )

                metadata: Dict[str, Any] = {
                    "malware":     malware,
                    "threat_type": threat_type,
                    "reporter":    (row.get("reporter") or "").strip(),
                    "source":      "threatfox_export",
                }
                if port is not None:
                    metadata["port"] = port
                ref = row.get("reference", "").strip()
                if ref and ref != "None":
                    metadata["reference"] = ref

                iocs.append(self._make_ioc(
                    ioc_type=ioc_type,
                    value=ioc_value,
                    tags=_build_tags(malware, threat_type, tags_raw),
                    threat_score=None,
                    confidence=confidence,
                    metadata=metadata,
                    mitre_techniques=[],
                    first_seen=first_seen,
                ))
            except Exception:
                continue
        return iocs

    def _parse_hostfile(
        self, raw_text: str, seen: set
    ) -> List[Dict[str, Any]]:
        """
        Parse ThreatFox hostfile format:
            127.0.0.1 malicious-domain.com   # optional inline comment
        Every non-comment line has IP in col[0] and domain in col[1].
        """
        iocs = []
        for line in raw_text.splitlines():
            line = line.strip()
            if not line or line.startswith("#"):
                continue

            # Strip any inline comment
            line = line.split("#")[0].strip()
            parts = line.split()
            if len(parts) < 2:
                continue

            domain = parts[1].strip().lower()
            if not domain or domain == "localhost":
                continue

            dedup_key = f"domain:{domain}"
            if dedup_key in seen:
                continue
            seen.add(dedup_key)

            iocs.append(self._make_ioc(
                ioc_type="domain",
                value=domain,
                tags=["threatfox", "c2", "hostfile"],
                threat_score=None,
                confidence=75,
                metadata={"source": "threatfox_hostfile"},
                mitre_techniques=[],
                first_seen=None,
            ))
        return iocs

    # ── static helpers ───────────────────────────────────────────────────────

    @staticmethod
    def _split_ip_port(
        ioc_type: str, value: str
    ) -> Tuple[str, Optional[int]]:
        """
        For ip:port IOCs, split the value and return (ip, port).
        For everything else return (value, None).
        Port is preserved in metadata — don't discard it silently.
        """
        if ioc_type == "ip" and ":" in value:
            parts = value.split(":", 1)
            ip = parts[0]
            try:
                return ip, int(parts[1])
            except (IndexError, ValueError):
                return ip, None
        return value, None

    @staticmethod
    def _map_type(raw_type: str) -> str:
        return {
            "ip:port":    "ip",
            "domain":     "domain",
            "url":        "url",
            "md5_hash":   "hash",
            "sha256_hash": "hash",
            "sha1_hash":  "hash",
        }.get(raw_type, "")


# ── module-level helpers (pure functions, no self needed) ────────────────────

def _parse_datetime(value: Optional[str]) -> Optional[datetime]:
    """
    Parse ThreatFox timestamps.
    Both formats seen in the wild:
      "2026-04-06 09:30:33 UTC"  (API response)
      "2026-04-06 09:30:33"      (CSV export)
    """
    if not value:
        return None
    clean = value.strip().replace(" UTC", "")
    try:
        return datetime.strptime(clean, "%Y-%m-%d %H:%M:%S").replace(
            tzinfo=timezone.utc
        )
    except (ValueError, AttributeError):
        return None


def _is_expired(dt: Optional[datetime]) -> bool:
    """
    Return True if the IOC is older than 180 days.
    ThreatFox enforces this expiry server-side since 2025-05-01, but we
    apply it client-side too to catch anything that slipped through or was
    stored before the policy came into effect.
    """
    if dt is None:
        return False
    return (datetime.now(timezone.utc) - dt) > timedelta(days=_MAX_IOC_AGE_DAYS)


def _build_tags(
    malware: str, threat_type: str, extra: List[str]
) -> List[str]:
    """Build a deduplicated tag list, preserving insertion order."""
    tags: List[str] = ["threatfox"]
    if malware:
        tags.append(malware.lower().replace(" ", "-"))
    if threat_type:
        tags.append(threat_type.lower())
    for t in extra:
        if t:
            tags.append(str(t).lower())
    # dict.fromkeys preserves order and removes duplicates
    return list(dict.fromkeys(tags))
