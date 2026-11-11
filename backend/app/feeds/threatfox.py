"""ThreatFox (abuse.ch) feed connector — the keyed recent.csv export, read by id cursor."""

import csv
from datetime import datetime, timezone, timedelta
from typing import Any, Dict, List, Optional, Tuple

import structlog

from app.feeds.base import (
    BaseFeed,
    FeedConfigurationError,
    SHAPE_SLIDING_WINDOW,
    error_text,
    iter_lines,
    parse_id_cursor,
    take_after_cursor,
)
from app.utils.sanitize import redact_secrets

logger = structlog.get_logger()

# ThreatFox expires IOCs older than 6 months (policy enforced since 2025-05-01).
# Validated live: https://threatfox.abuse.ch/export/ — "Since 2025-05-01, we are
# expiring IOCs that are older than 6 months."
_MAX_IOC_AGE_DAYS = 180

# Column order of the export. The header line is commented out in the file, so the
# names are defined here rather than read. 15 fields on every one of 8,064 rows,
# measured 2026-11-11.
_CSV_FIELDNAMES = [
    "first_seen_utc", "ioc_id", "ioc_value", "ioc_type", "threat_type",
    "fk_malware", "malware_alias", "malware_printable", "last_seen_utc",
    "confidence_level", "is_compromised", "reference", "tags", "anonymous",
    "reporter",
]
_ID, _FIRST_SEEN, _LAST_SEEN = 1, 0, 8

_TS_FMT = "%Y-%m-%d %H:%M:%S"


class ThreatFoxFeed(BaseFeed):
    name = "ThreatFox"
    slug = "threatfox"
    feed_type = "csv"
    # The advertised source, shown by GET /api/v1/feeds. `{KEY}` is a literal
    # placeholder: this attribute is served to clients and must never hold the key.
    url = "https://threatfox-api.abuse.ch/v2/files/exports/{KEY}/recent.csv"
    description = "ThreatFox shares IOCs associated with malware families"
    # REQUIRED. Until 2026-11 this was False and the connector fetched four keyless
    # CSV exports and a hostfile from threatfox.abuse.ch, all wrapped in
    # try/except-return-empty, plus the JSON API (days=1) with the key optional. The
    # keyless files now answer 410 Gone, so only the API was still producing anything.
    requires_api_key = True
    api_key_env = "THREATFOX_API_KEY"
    source_shape = SHAPE_SLIDING_WINDOW
    default_sync_frequency = 1800

    _EXPORT_BASE = "https://threatfox-api.abuse.ch/v2/files/exports"

    # ── What the file is ─────────────────────────────────────────────────────
    # MEASURED 2026-11-11 from two snapshots six hours apart (09:10 and 15:10 UTC):
    # 7,933 and 8,064 rows, 1.87 MB. The file is the union of two sets:
    #   - every IOC ADDED in the last ~48 hours. In both snapshots the oldest row
    #     with an empty last_seen_utc was 48.2 h old, and every row older than 48 h
    #     had last_seen_utc set;
    #   - older IOCs RE-SIGHTED recently, back to first_seen 2021-09-18. They enter
    #     the file when their last_seen_utc moves (52 such rows arrived in the six
    #     hours, first_seen June to 8 November) and leave when it goes stale.
    #
    # _MEASURED_WINDOW_HOURS is the ADDITIONS window, 48.2 h. It replaces 4237.04 h,
    # measured 2026-07-30 as the first_seen span of the keyless exports -- which is
    # the re-sighting tail reaching back to the 180-day expiry, not how far back the
    # file covers new IOCs. That figure gave this feed a "~706x" margin; the real
    # margin against the 6-hour governing interval is ~8x, the same as MalwareBazaar.
    _MEASURED_WINDOW_HOURS = 48.2

    # ── Why an id cursor, and what it does not see ───────────────────────────
    # Each sync takes only rows whose ioc_id is above the stored cursor. Measured
    # across the two snapshots, every row added between them had an id above the
    # first file's maximum; the API ids missing from a same-time file were all above
    # that file's maximum (the file regenerates every few minutes) and present in the
    # next one. No row was published late beneath the cursor.
    #
    # The alternatives, re-read share measured at the six-hour gap:
    #   JSON API, days=1 (what was live) .... 1,141 of 1,430 rows already seen (79.8%)
    #   whole recent.csv every sync ......... 7,732 of 8,063 rows already seen (95.9%)
    #   recent.csv above an id cursor ....... 0
    # Every re-read is an UPDATE sent one row per round trip (151-159 ms each in
    # production) and a sighting_count increment (#105). The whole file would cost
    # ~20 minutes of UPDATEs per sync to learn about a few dozen re-sightings.
    #
    # THE TRADE: re-sightings carry an old id, so the cursor does not see them, and
    # last_seen does not advance when ThreatFox re-sights an IOC already stored. The
    # JSON API this replaces did not return them either (0 of the 52), so this is not
    # a regression. The cursor also widens the loss-free gap between syncs from the
    # API's 24 h to the file's 48 h.
    #
    # ioc_id is NOT monotonic in first_seen_utc (178 inversions on the 2026-11-11
    # file), which is why the cursor is the id and not a timestamp. Ids are also not
    # dense (31-37 gaps in the top 3,000), so a jump between the cursor and the file's
    # lowest id does not mean rows were lost; the time-based continuity check below
    # is what reports a gap.
    #
    # _MAX_ROWS_PER_SYNC: the memory guard, shared reasoning with URLhaus (see
    # urlhaus.py, where the 20,000 figure is derived). This file is ~8k rows today,
    # so the cap does not bind; it is there so that abuse.ch growing the file, as it
    # did URLhaus's seven-fold, cannot turn one sync into an unbounded read.
    _MAX_ROWS_PER_SYNC = 20_000

    # With no cursor -- the first sync after this change deploys, a fresh install, a
    # re-created feed row -- take rows first seen within this span of the newest one.
    # Matches the additions window, so a cold start takes what the file carries as
    # additions and leaves the re-sighting tail alone, as steady state does.
    _COLD_START_LOOKBACK = timedelta(hours=48)

    # ── fetch ────────────────────────────────────────────────────────────────

    async def fetch(self) -> Dict[str, Any]:
        """The keyed recent.csv. Raises on a missing key or a failed download."""
        if not self.api_key:
            raise FeedConfigurationError(
                "THREATFOX_API_KEY is not set. abuse.ch withdrew the keyless ThreatFox "
                "exports (threatfox.abuse.ch/export/csv/.../recent/ answers 410 Gone); "
                "an abuse.ch Auth-Key is required, and the feed row's api_key_env must "
                "name THREATFOX_API_KEY."
            )
        logger.info("threatfox_fetch_start", cursor=self.sync_cursor)
        try:
            # The URL carries the key in its path, and httpx puts the URL in its
            # exception text -- redact before it can reach a log or the feed row.
            resp = await self._fetch_url(f"{self._EXPORT_BASE}/{self.api_key}/recent.csv")
        except Exception as exc:
            raise RuntimeError(
                "ThreatFox recent.csv fetch failed: " + redact_secrets(error_text(exc))
            ) from None
        logger.info("threatfox_recent_csv_fetched", bytes=len(resp.text))
        return {"recent_csv": resp.text}

    # ── parse ────────────────────────────────────────────────────────────────

    async def parse(self, raw_data: Dict[str, Any]) -> List[Dict[str, Any]]:
        text = raw_data.get("recent_csv", "")
        if not text:
            return []
        rows, next_id = self._select_rows(text)
        if next_id is not None:
            self.next_cursor = str(next_id)
        iocs = self._rows_to_iocs(rows)
        logger.info(
            "threatfox_parse_complete",
            total_iocs=len(iocs),
            cursor_in=self.sync_cursor,
            cursor_out=self.next_cursor,
        )
        return iocs

    def _select_rows(self, text: str) -> Tuple[List[List[str]], Optional[int]]:
        """Pick the rows this sync ingests, and record the file's additions window."""
        cursor = parse_id_cursor(self.sync_cursor)
        if self.sync_cursor is not None and cursor is None:
            logger.warning("threatfox_cursor_unreadable", cursor=self.sync_cursor)

        # Pass 1: the window. Timestamps are fixed-width "YYYY-MM-DD HH:MM:SS" and
        # compared as strings. The window's START is the oldest row never re-sighted
        # (empty last_seen_utc): that is how far back the file covers additions. A
        # re-sighted row's first_seen says nothing about coverage -- it reaches back to
        # 2021 -- and using it would make the continuity check unable to fire.
        expiry = (datetime.now(timezone.utc)
                  - timedelta(days=_MAX_IOC_AGE_DAYS)).strftime(_TS_FMT)
        lo: Optional[str] = None
        hi: Optional[str] = None
        for row in _data_rows(text):
            first = _field(row, _FIRST_SEEN)
            if len(first) != 19:
                continue
            hi = first if hi is None or first > hi else hi
            if not _field(row, _LAST_SEEN) and first >= expiry:
                lo = first if lo is None or first < lo else lo
        if lo is not None:
            self.record_observed_window([_parse_datetime(lo), _parse_datetime(hi)])

        newest = _parse_datetime(hi)
        cold_start_from = (
            (newest - self._COLD_START_LOOKBACK).strftime(_TS_FMT)
            if (cursor is None and newest is not None) else None
        )

        def candidates():
            for row in _data_rows(text):
                try:
                    rid = int(_field(row, _ID))
                except ValueError:
                    continue
                if cursor is not None:
                    if rid <= cursor:
                        continue
                elif cold_start_from is None or _field(row, _FIRST_SEEN) < cold_start_from:
                    continue
                yield rid, row

        taken, last_id, eligible = take_after_cursor(candidates(), self._MAX_ROWS_PER_SYNC)

        if cursor is None:
            logger.warning(
                "threatfox_cold_start",
                lookback_hours=int(self._COLD_START_LOOKBACK.total_seconds() // 3600),
                rows_taken=len(taken),
            )
        if eligible > len(taken):
            logger.warning(
                "threatfox_backlog_capped",
                eligible=eligible, taken=len(taken), remaining=eligible - len(taken),
            )
        return taken, last_id

    def _rows_to_iocs(self, rows: List[List[str]]) -> List[Dict[str, Any]]:
        iocs: List[Dict[str, Any]] = []
        seen: set = set()
        for raw in rows:
            try:
                row = dict(zip(_CSV_FIELDNAMES, raw))
                ioc_value = (row.get("ioc_value") or "").strip()
                ioc_type = self._map_type((row.get("ioc_type") or "").strip())
                if not ioc_value or not ioc_type:
                    continue

                ioc_value, port = self._split_ip_port(ioc_type, ioc_value)

                first_seen = _parse_datetime(row.get("first_seen_utc"))
                if _is_expired(first_seen):
                    continue

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
                    if tags_raw_str and tags_raw_str != "None" else []
                )

                metadata: Dict[str, Any] = {
                    "malware":     malware,
                    "threat_type": threat_type,
                    "reporter":    (row.get("reporter") or "").strip(),
                    "source":      "threatfox_export",
                }
                if port is not None:
                    metadata["port"] = port
                ref = (row.get("reference") or "").strip()
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

def _data_rows(text: str):
    """Yield parsed CSV rows, skipping the # comment block. Lazy: no line list."""
    for row in csv.reader(iter_lines(text), skipinitialspace=True):
        if not row or row[0].startswith("#"):
            continue
        yield row


def _field(row: List[str], index: int) -> str:
    return row[index].strip() if len(row) > index else ""


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
        return datetime.strptime(clean, _TS_FMT).replace(tzinfo=timezone.utc)
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
