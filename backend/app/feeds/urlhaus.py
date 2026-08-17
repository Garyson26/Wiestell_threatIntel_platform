"""URLhaus (abuse.ch) feed connector — URL IOCs + payload hash IOCs + domain IOCs."""

import csv
import io
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Tuple

import structlog

from app.feeds.base import BaseFeed, SHAPE_SLIDING_WINDOW
from app.utils.sanitize import redact_secrets

logger = structlog.get_logger()

# ── CSV column names — from the comment header line in the URLhaus CSV ───────
# Header line in file: # id,dateadded,url,url_status,last_online,threat,tags,urlhaus_link,reporter
# Confirmed live April 2026 from https://urlhaus.abuse.ch/downloads/csv_recent/
_CSV_FIELDNAMES = [
    "id", "dateadded", "url", "url_status", "last_online",
    "threat", "tags", "urlhaus_link", "reporter",
]

# ── Payload CSV column names (confirmed from URLhaus API response structure) ─
# API fields: md5_hash, sha256_hash, file_type, file_size, signature, firstseen
#
# NOTE: "virustotal" here is a *column name in URLhaus's own CSV export*, not a
# reference to the removed VirusTotal integration. It must match the upstream
# header exactly or csv.DictReader misaligns every subsequent field. Do not remove
# it while cleaning up VirusTotal references.
_PAYLOAD_FIELDNAMES = [
    "md5_hash", "sha256_hash", "file_type", "file_size",
    "signature", "firstseen", "urlhaus_download",
    "virustotal", "imphash", "ssdeep", "tlsh", "magika",
]

# Timestamp formats seen in URLhaus data
_TS_FMT        = "%Y-%m-%d %H:%M:%S"   # CSV export: "2026-04-06 14:15:12"
_TS_FMT_UTC    = "%Y-%m-%d %H:%M:%S"   # same format — strip " UTC" if present


class URLhausFeed(BaseFeed):
    name = "URLhaus"
    slug = "urlhaus"
    feed_type = "api"
    url = "https://urlhaus.abuse.ch/downloads/csv_recent/"
    description = "URLhaus collects and shares malicious URLs used for malware distribution"
    requires_api_key = False  # Optional - works without key but provides more data with key
    api_key_env = "URLHAUS_API_KEY"
    # csv_recent is a rolling window, so an interval longer than it loses URLs
    # silently. Measured per sync rather than assumed — see BaseFeed.rolling_window.
    # A rolling window: csv_recent holds the last N hours, so a sync interval longer
    # than the window loses records silently. Gap monitoring is on for this shape.
    source_shape = SHAPE_SLIDING_WINDOW

    # MEASURED 2026-07-30 from csv_recent itself: 15,524 URLs spanning
    #   2026-06-30 00:00:15Z .. 2026-07-30 13:23:30Z  =  30d 13h  (733.39 hours)
    # "Recent" means roughly the last month, NOT the last 48 hours that the name
    # suggests. Against a 6-hour governing interval that is a ~122x margin, so this
    # feed is in no danger; the check is here to notice if abuse.ch ever shortens it.
    _MEASURED_WINDOW_HOURS = 733.39

    # Only ONE of the four fetched sources is a time window, and the continuity
    # check is only meaningful against that one:
    #   recent_csv   rolling window of recently-added URLs   <- the window
    #   online_csv   URLs *currently* online — a status selection, not a window. A
    #                URL online for a year makes its minimum a year old, which
    #                would mask every real gap.
    #   payloads_csv / hostfile   keyed exports, present only with an Auth-Key
    _WINDOW_SOURCE = "recent_csv"
    default_sync_frequency = 900        # 15 minutes

    # ── Free no-auth endpoints (confirmed live April 2026) ───────────────────
    # csv_recent:  all URLs recently added (online + offline)
    # csv_online:  ONLY currently active malware sites — use for blocking tier
    _URL_RECENT = "https://urlhaus.abuse.ch/downloads/csv_recent/"
    _URL_ONLINE = "https://urlhaus.abuse.ch/downloads/csv_online/"

    # ── Auth-required v2 endpoints — Auth-Key embedded in URL PATH ───────────
    # Pattern: https://urlhaus-api.abuse.ch/v2/files/exports/{KEY}/{file}
    _EXPORT_BASE = "https://urlhaus-api.abuse.ch/v2/files/exports"

    # payloads.csv — MD5+SHA256 hashes of malware downloaded from tracked URLs
    # hostfile     — malware domains in /etc/hosts format (active + past 48h)

    # ── fetch ────────────────────────────────────────────────────────────────

    async def fetch(self) -> Dict[str, Any]:
        logger.info("urlhaus_fetch_start")
        results: Dict[str, Any] = {}

        # 1. Recent URLs CSV — no auth required (your existing endpoint)
        try:
            resp = await self.client.get(self._URL_RECENT)
            resp.raise_for_status()
            results["recent_csv"] = resp.text
            logger.info("urlhaus_recent_csv_fetched")
        except Exception as exc:
            logger.warning("urlhaus_recent_csv_failed", error=redact_secrets(exc))
            results["recent_csv"] = ""

        # 2. Online-only URLs CSV — no auth, active malware sites only
        #    Lower false positive rate than recent_csv — use for blocking tier
        try:
            resp = await self.client.get(self._URL_ONLINE)
            resp.raise_for_status()
            results["online_csv"] = resp.text
            logger.info("urlhaus_online_csv_fetched")
        except Exception as exc:
            logger.warning("urlhaus_online_csv_failed", error=redact_secrets(exc))
            results["online_csv"] = ""

        # 3. Payloads CSV — Auth-Key in URL path — hash IOCs from malware downloads
        #    Note: not all payloads are malicious (a URL can serve benign content
        #    after being cleaned up). Apply the signature filter in parse().
        if self.api_key:
            try:
                url = f"{self._EXPORT_BASE}/{self.api_key}/payloads.csv"
                resp = await self.client.get(url)
                resp.raise_for_status()
                results["payloads_csv"] = resp.text
                logger.info("urlhaus_payloads_csv_fetched")
            except Exception as exc:
                logger.warning("urlhaus_payloads_csv_failed", error=redact_secrets(exc))
                results["payloads_csv"] = ""
        else:
            results["payloads_csv"] = ""

        # 4. Hostfile — Auth-Key in URL path — domain IOCs
        #    Contains only active malware domains + domains added in past 48h.
        #    Excludes Tranco Top 1M domains (low FP rate by design).
        if self.api_key:
            try:
                url = f"{self._EXPORT_BASE}/{self.api_key}/hostfile"
                resp = await self.client.get(url)
                resp.raise_for_status()
                results["hostfile"] = resp.text
                logger.info("urlhaus_hostfile_fetched")
            except Exception as exc:
                logger.warning("urlhaus_hostfile_failed", error=redact_secrets(exc))
                results["hostfile"] = ""
        else:
            results["hostfile"] = ""

        return results

    # ── parse ────────────────────────────────────────────────────────────────

    async def parse(self, raw_data: Dict[str, Any]) -> List[Dict[str, Any]]:
        iocs: List[Dict[str, Any]] = []
        seen_urls: set = set()    # dedup URL IOCs across recent + online CSVs
        seen_hashes: set = set()  # dedup hash IOCs from payloads CSV
        seen_domains: set = set() # dedup domain IOCs from hostfile

        # recent_csv and online_csv use the same format — merge with dedup.
        # Only recent_csv contributes to the observed window; see _WINDOW_SOURCE.
        for key in ("recent_csv", "online_csv"):
            text = raw_data.get(key, "")
            if text:
                iocs.extend(self._parse_url_csv(
                    text, seen_urls, record_window=(key == self._WINDOW_SOURCE)
                ))

        payloads_text = raw_data.get("payloads_csv", "")
        if payloads_text:
            iocs.extend(self._parse_payloads_csv(payloads_text, seen_hashes))

        hostfile_text = raw_data.get("hostfile", "")
        if hostfile_text:
            iocs.extend(self._parse_hostfile(hostfile_text, seen_domains))

        logger.info("urlhaus_parse_complete", total_iocs=len(iocs))
        return iocs

    # ── source parsers ───────────────────────────────────────────────────────

    def _parse_url_csv(
        self, raw_text: str, seen: set, record_window: bool = False
    ) -> List[Dict[str, Any]]:
        """
        Parse URLhaus recent/online CSV exports.

        CSV format (confirmed live April 2026):
          Header in comment: # id,dateadded,url,url_status,last_online,threat,tags,urlhaus_link,reporter
          Data rows: all fields quoted, comma-separated.

        Key notes:
        - Tags field contains literal string "None" when empty — must be filtered.
        - url_status: "online" (active) or "offline" (taken down).
        - We keep both online and offline URLs but score them differently.
        """
        iocs = []
        window_timestamps: List[Optional[datetime]] = []
        # Strip comment lines, pass fieldnames manually (header is commented out)
        data_lines = [
            line for line in raw_text.splitlines()
            if line.strip() and not line.startswith("#")
        ]
        if not data_lines:
            return []

        reader = csv.DictReader(
            io.StringIO("\n".join(data_lines)),
            fieldnames=_CSV_FIELDNAMES,
            quotechar='"',
            skipinitialspace=True,
        )

        for row in reader:
            try:
                url_value  = (row.get("url") or "").strip()
                url_status = (row.get("url_status") or "").strip()
                threat     = (row.get("threat") or "").strip()
                tags_str   = (row.get("tags") or "").strip()
                dateadded  = (row.get("dateadded") or "").strip()
                last_online = (row.get("last_online") or "").strip()
                reporter   = (row.get("reporter") or "").strip()

                if not url_value or not url_value.startswith("http"):
                    continue
                if url_value in seen:
                    continue
                seen.add(url_value)

                # Score by status — online sites are actively serving malware
                if url_status == "online":
                    score = 80
                elif url_status == "offline":
                    score = 40
                else:
                    score = 65

                tags = ["urlhaus", "malware-distribution"]
                if threat:
                    tags.append(threat.lower())
                if tags_str and tags_str != "None":
                    # Tags field is comma-separated inside the cell
                    tags.extend([
                        t.strip().lower() for t in tags_str.split(",")
                        if t.strip() and t.strip() != "None"
                    ])

                first_seen = _parse_ts(dateadded)
                last_seen  = _parse_ts(last_online) if last_online else None
                if record_window:
                    window_timestamps.append(first_seen)

                iocs.append(self._make_ioc(
                    ioc_type="url",
                    value=url_value,
                    tags=list(dict.fromkeys(tags)),  # deduplicate tags
                    threat_score=score,
                    confidence=70,
                    metadata={
                        "status":   url_status,
                        "threat":   threat,
                        "reporter": reporter,
                        "source":   "urlhaus",
                    },
                    mitre_techniques=[],
                    first_seen=first_seen,
                    last_seen=last_seen,
                ))
            except (IndexError, ValueError, Exception):
                continue

        if record_window:
            self.record_observed_window(window_timestamps)

        return iocs

    def _parse_payloads_csv(
        self, raw_text: str, seen: set
    ) -> List[Dict[str, Any]]:
        """
        Parse the URLhaus payloads CSV export.

        Contains MD5 and SHA256 hashes of files downloaded from malware URLs.
        Confirmed column names from URLhaus API JSON: md5_hash, sha256_hash,
        file_type, file_size, signature, firstseen.

        IMPORTANT: Not all payloads are malicious — a URL can serve benign
        content after being cleaned up. Only produce IOCs for rows where
        signature is non-null, or apply this rule: all hashes are stored
        but with lower confidence when signature is missing.
        """
        header_line, data_lines = _split_csv(raw_text)
        if not data_lines:
            # If CSV has a proper header, use DictReader without fieldnames
            # If it uses comment-style header, use hardcoded _PAYLOAD_FIELDNAMES
            data_lines_raw = [
                l for l in raw_text.splitlines()
                if l.strip() and not l.startswith("#")
            ]
            if not data_lines_raw:
                return []
            reader = csv.DictReader(
                io.StringIO("\n".join(data_lines_raw)),
                fieldnames=_PAYLOAD_FIELDNAMES,
                quotechar='"',
                skipinitialspace=True,
            )
        else:
            reader = csv.DictReader(
                io.StringIO(header_line + "\n" + "\n".join(data_lines)),
                quotechar='"',
                skipinitialspace=True,
            )

        iocs = []
        for row in reader:
            try:
                sha256    = (row.get("sha256_hash") or "").strip().lower()
                md5       = (row.get("md5_hash") or "").strip().lower()
                file_type = (row.get("file_type") or "").strip()
                signature = (row.get("signature") or "").strip()
                firstseen = (row.get("firstseen") or "").strip()

                # Confidence: higher when malware family is identified
                confidence = 75 if signature and signature != "None" else 55

                tags = ["urlhaus", "payload"]
                if file_type:
                    tags.append(file_type.lower())
                if signature and signature != "None":
                    tags.append(signature.lower().replace(" ", "-"))

                first_seen = _parse_ts(firstseen)
                shared_meta = {
                    "file_type": file_type,
                    "signature": signature if signature != "None" else None,
                    "source":    "urlhaus_payload",
                }

                for hash_type, val in (("sha256", sha256), ("md5", md5)):
                    if not val or val in seen:
                        continue
                    seen.add(val)
                    iocs.append(self._make_ioc(
                        ioc_type="hash",
                        value=val,
                        tags=list(dict.fromkeys(tags)),
                        threat_score=None,
                        confidence=confidence,
                        metadata={**shared_meta, "hash_type": hash_type},
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
        Parse URLhaus hostfile export.

        Format: 127.0.0.1 malicious-domain.com  # optional comment
        Contains only active malware domains + domains added in past 48h.
        Tranco Top 1M domains are excluded by URLhaus before export.
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
            if domain in seen:
                continue
            seen.add(domain)

            iocs.append(self._make_ioc(
                ioc_type="domain",
                value=domain,
                tags=["urlhaus", "malware-distribution", "hostfile"],
                threat_score=70,
                confidence=75,
                metadata={"source": "urlhaus_hostfile"},
                mitre_techniques=[],
                first_seen=None,
            ))
        return iocs


# ── module-level helpers ─────────────────────────────────────────────────────

def _parse_ts(value: Optional[str]) -> Optional[datetime]:
    """
    Parse a URLhaus timestamp string to a timezone-aware datetime.

    Formats seen in URLhaus data:
      "2026-04-06 14:15:12"       — CSV export (no UTC suffix)
      "2026-04-06 14:15:12 UTC"   — some API responses add " UTC"

    Always returns UTC-aware datetime or None.
    """
    if not value:
        return None
    clean = value.strip().replace(" UTC", "")
    try:
        return datetime.strptime(clean, _TS_FMT).replace(tzinfo=timezone.utc)
    except (ValueError, AttributeError):
        return None


def _split_csv(raw_text: str) -> Tuple[str, List[str]]:
    """
    Split a CSV that may have a real header row (not commented out).
    Returns (header_line, data_lines).
    Returns ("", []) if there is insufficient content.
    """
    non_comment = [
        l for l in raw_text.splitlines()
        if l.strip() and not l.startswith("#")
    ]
    if len(non_comment) < 2:
        return "", []
    return non_comment[0], non_comment[1:]
