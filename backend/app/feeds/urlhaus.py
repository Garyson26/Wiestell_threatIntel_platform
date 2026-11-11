"""URLhaus (abuse.ch) feed connector — URL IOCs from the keyed recent.csv export."""

import csv
import re
from datetime import datetime, timedelta, timezone
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

# ── CSV column names — from the comment header line in the export ────────────
# Header line in file: # id,dateadded,url,url_status,last_online,threat,tags,urlhaus_link,reporter
# Unchanged between the retired keyless csv_recent (confirmed April 2026) and the
# keyed recent.csv (confirmed 2026-11-11).
_CSV_FIELDNAMES = [
    "id", "dateadded", "url", "url_status", "last_online",
    "threat", "tags", "urlhaus_link", "reporter",
]

# Timestamp format in the export: "2026-04-06 14:15:12" (some API responses add " UTC")
_TS_FMT = "%Y-%m-%d %H:%M:%S"
# The same format as a pattern, for comparing timestamps as strings without parsing.
_TS_RE = re.compile(r"\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}$")


class URLhausFeed(BaseFeed):
    name = "URLhaus"
    slug = "urlhaus"
    feed_type = "csv"
    # The advertised source, shown by GET /api/v1/feeds. `{KEY}` is a literal
    # placeholder: this attribute is served to clients and must never hold the key.
    url = "https://urlhaus-api.abuse.ch/v2/files/exports/{KEY}/recent.csv"
    description = "URLhaus collects and shares malicious URLs used for malware distribution"
    # REQUIRED since abuse.ch withdrew the keyless exports. Until 2026-11 this was
    # False: urlhaus.abuse.ch/downloads/csv_recent/ and csv_online/ served keyless
    # (csv_recent measured 2026-07-30: 15,524 URLs). Both now answer 410 Gone.
    requires_api_key = True
    api_key_env = "URLHAUS_API_KEY"
    source_shape = SHAPE_SLIDING_WINDOW
    default_sync_frequency = 900        # 15 minutes; the cron interval governs

    # ── The export ───────────────────────────────────────────────────────────
    # https://urlhaus-api.abuse.ch/v2/files/exports/{KEY}/{file}. Probed with a valid
    # key on 2026-11-11: recent.csv, online.csv, full.csv.zip, recent.json and
    # online.json exist; payloads.csv and hostfile -- the two keyed files this
    # connector used to fetch -- answer 404 "Invalid export file name".
    _EXPORT_BASE = "https://urlhaus-api.abuse.ch/v2/files/exports"

    # MEASURED 2026-11-11 from the keyed recent.csv itself: 114,118 URLs, dateadded
    #   2026-10-12 00:02:06Z .. 2026-11-11 08:47:10Z  =  728.75 hours (30.4 days)
    # Previous measurement, keyless csv_recent, 2026-07-30: 15,524 URLs over 733.39 h.
    # Same span, ~7x the rows: abuse.ch did not only move the file behind a key, it
    # changed what the file contains. Sizing decisions made against 15.5k rows do not
    # carry over -- see _MAX_ROWS_PER_SYNC.
    _MEASURED_WINDOW_HOURS = 728.75

    # The window source for the continuity check. Kept as a named constant because
    # tests pin it; online.csv, which used to sit beside it, is no longer fetched.
    _WINDOW_SOURCE = "recent_csv"

    # ── Incremental reads: an id cursor, capped per sync ─────────────────────
    #
    # WHY NOT READ THE WHOLE FILE. Parsing all 114,118 rows into IOC dicts was
    # measured locally at a 358 MB peak Python allocation (196 MB retained) -- before
    # the application's own baseline -- against a 512 MB Render instance. A full read
    # does not fit. And it would be ~99% re-reads of URLs already stored.
    #
    # So each sync takes only rows whose `id` is above the stored cursor. URLhaus ids
    # are strictly increasing with `dateadded` (0 inversions across 114,135 rows,
    # measured 2026-11-11), so "above the cursor" is exactly "added since last time".
    #
    # _MAX_ROWS_PER_SYNC is the MEMORY GUARD and applies to EVERY sync, not just the
    # first. Without it, a cursor older than the file -- syncs stopped for longer than
    # the 30-day window -- would select every row and reproduce the full read. Rows are
    # taken oldest-first, so a backlog larger than the cap drains over the following
    # syncs instead of being skipped, and the cursor advances only to the last row
    # TAKEN -- never to the file's maximum, which would skip the capped remainder
    # permanently (the same shape as a page-capped cursor running ahead of the pages).
    #
    # SIZING. Everything below was measured 2026-11-11 against the real keyed file;
    # nothing is inferred from averages.
    #
    # Arrivals (dateadded, per UTC day): median 993/day, mean 3,874/day, and a burst
    # on 23-26 Oct 2026 of 13,448 / 20,965 / 23,441 / 19,829 -- 18,002 rows in the
    # busiest 6-hour window. Syncs: 18 sweep starts in 6.65 days on Render (~2.7/day,
    # not the 4/day the cron asks for), largest gap 13h15m.
    #
    # Memory scales linearly, so a future cap can be sized without re-measuring:
    #   Python allocations (tracemalloc): ~2 KB per row taken, at 5k/10k/20k/30k.
    #   Process RSS, full path -- download held, parse, ingest_iocs into MariaDB --
    #   on Linux / Python 3.11.9 (Render's runtime): +85 MB flat up to ~10k rows,
    #   because holding the 28.3 MB file as text dominates; past that,
    #   ~23 MB + ~5 MB per 1,000 rows. Measured: 10k +85, 20k +124, 30k +175 MB.
    #   RSS is ~2x the Python peak (175 vs 88 MB at 30k, 124 vs 69 MB at 20k); the
    #   allocator, not ingestion, is the gap
    #   (ingest_iocs itself adds ~17 MB of Python allocations at 30k).
    # Render memory stayed at 134-147 MB all week (hourly) and 140.6-145.6 MB
    # minute-by-minute through a sweep that held Blocklist.de's 26,339 rows.
    #
    # THE RULE: the projected peak (147 MB observed + the measured increment) must
    # leave free at least the largest increment measured (175 MB), i.e. stay under
    # ~60% of the 512 MB instance. The reserve is that large because the failure
    # mode is not bounded: on an OOM the cursor is not saved, so the next sweep
    # re-takes the same rows and dies the same way -- a loop that stops the feed and
    # restarts the API every sweep. A cap that is too small instead loses rows only
    # after a >30-day outage, and says so (urlhaus_cursor_behind_window).
    #   30,000 -> 322 MB (63%)  fails the rule
    #   20,000 -> 271 MB (53%)  passes
    #
    # What 20,000 buys, replaying the real arrival series through this logic:
    #   - Normal operation is lossless: the October burst backs up at most ~20k rows,
    #     the oldest ~1 day old, against a 30-day expiry.
    #   - After a >30-day outage the walk starts at the end of the file that ages out
    #     next. That alone is not enough: if that end is a burst, it ages out faster
    #     than a capped sync takes it. Worst case at 20,000: 0 rows lost at 6-hourly
    #     syncs, 1,785 at 9-hourly, 3,206 at the 13h15m gap (5,000 would have lost
    #     15,185 / 30,185 / 43,679). Losslessness at every measured gap needs 30,000,
    #     which the memory rule excludes.
    #   - Catch-up: a cursor older than the whole file (~114k rows) clears in ~6
    #     syncs, about 2.2 days at the measured cadence.
    #
    # Time is not the binding constraint. All 17 sweeps that week ran 73-145 minutes
    # to completion; the 15-minute idle spin-down never interrupted one. New rows
    # ingest at 39-52 ms each in production (MalwareBazaar, batches of 117-237), so
    # a full 20,000-row catch-up is ~13-17 min -- an extrapolation, flagged as such.
    _MAX_ROWS_PER_SYNC = 20_000

    # _COLD_START_LOOKBACK is NOT the window this feed operates on. It applies only
    # when there is no cursor to continue from: the first sync after this change
    # deploys, a fresh install, or a feed row that was deleted and re-created. It
    # decides where an uncursored walk STARTS; the row cap above still bounds it.
    #
    # It does NOT bound memory -- the row cap does that, whatever the look-back. It
    # was originally sized on memory (7 days ~154 MB vs 30 days 451 MB, measured
    # before the selection streamed), and that reason no longer applies. What it
    # bounds now is a PRODUCT choice: how much history a fresh install ingests before
    # it starts tracking new URLs. A week (6,993 rows on the 2026-11-11 file, one
    # sync) is useful context for a new deployment. A month (all ~114k rows) would
    # spend about six syncs ingesting historical URLs, mostly offline, before the
    # cursor reached anything current. Change this value on that basis, not on memory.
    #
    # Anything older than this on a cold start is deliberately not ingested. With no
    # previous watermark the continuity check has nothing to compare against, so the
    # truncation is logged explicitly (urlhaus_cold_start) with the count skipped.
    _COLD_START_LOOKBACK = timedelta(days=7)

    # ── fetch ────────────────────────────────────────────────────────────────

    async def fetch(self) -> Dict[str, Any]:
        """The keyed recent.csv. Raises on a missing key or a failed download.

        Both used to be swallowed: each source was wrapped in try/except returning
        "", so a 410 on every source produced an empty, successful sync. That is how
        this feed reported healthy while ingesting nothing.
        """
        if not self.api_key:
            raise FeedConfigurationError(
                "URLHAUS_API_KEY is not set. abuse.ch withdrew the keyless URLhaus "
                "exports (urlhaus.abuse.ch/downloads/csv_recent/ answers 410 Gone); an "
                "abuse.ch Auth-Key is required, and the feed row's api_key_env must "
                "name URLHAUS_API_KEY."
            )
        logger.info("urlhaus_fetch_start", cursor=self.sync_cursor)
        try:
            # The URL carries the key in its path, and httpx puts the URL in its
            # exception text -- redact before it can reach a log or the feed row.
            resp = await self._fetch_url(f"{self._EXPORT_BASE}/{self.api_key}/recent.csv")
        except Exception as exc:
            raise RuntimeError(
                "URLhaus recent.csv fetch failed: " + redact_secrets(error_text(exc))
            ) from None
        logger.info("urlhaus_recent_csv_fetched", bytes=len(resp.text))
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
            "urlhaus_parse_complete",
            total_iocs=len(iocs),
            cursor_in=self.sync_cursor,
            cursor_out=self.next_cursor,
        )
        return iocs

    def _select_rows(self, text: str) -> Tuple[List[List[str]], Optional[int]]:
        """Pick the rows this sync ingests. Two passes, so memory stays bounded.

        Pass 1 reads only id and dateadded, to record the file's window and find its
        newest timestamp. Pass 2 keeps the raw rows above the cursor (or, with no
        cursor, newer than the cold-start bound) and hands them to the capped walk.
        Neither pass builds an IOC dict for a row that will not be ingested.
        """
        cursor = parse_id_cursor(self.sync_cursor)
        if self.sync_cursor is not None and cursor is None:
            logger.warning("urlhaus_cursor_unreadable", cursor=self.sync_cursor)

        # Pass 1. Timestamps are compared as STRINGS: the export's format is the
        # fixed-width "YYYY-MM-DD HH:MM:SS", which sorts lexicographically in time
        # order, so only the minimum and maximum are ever parsed. Calling strptime on
        # all ~114k rows was most of a 20-40 s parse locally, on a 0.1-CPU instance.
        min_id: Optional[int] = None
        lo: Optional[str] = None
        hi: Optional[str] = None
        dated = 0
        for row in _data_rows(text):
            try:
                rid = int(row[0])
            except (ValueError, IndexError):
                continue
            min_id = rid if min_id is None else min(min_id, rid)
            added = row[1].strip() if len(row) > 1 else ""
            if _TS_RE.match(added):
                dated += 1
                lo = added if lo is None or added < lo else lo
                hi = added if hi is None or added > hi else hi
        # The whole FILE's window, not just the rows taken: the continuity check asks
        # whether the source still reaches back to where the previous sync's file
        # ended, which is a property of the source, independent of the cursor.
        self.record_observed_window([_parse_ts(lo), _parse_ts(hi)])

        if cursor is not None and min_id is not None and min_id > cursor + 1:
            # Ids between the cursor and the file's oldest row aged out unread.
            # _check_window_continuity reports the same loss as a time gap on the
            # feed row; this names it in id terms in the log.
            logger.error(
                "urlhaus_cursor_behind_window",
                cursor=cursor, file_min_id=min_id, ids_missed=min_id - cursor - 1,
            )

        newest = _parse_ts(hi)
        cold_start_from = (
            (newest - self._COLD_START_LOOKBACK).strftime(_TS_FMT)
            if (cursor is None and newest is not None) else None
        )
        def candidates():
            for row in _data_rows(text):
                try:
                    rid = int(row[0])
                except (ValueError, IndexError):
                    continue
                if cursor is not None:
                    if rid <= cursor:
                        continue
                else:
                    added = row[1].strip() if len(row) > 1 else ""
                    if (cold_start_from is None or not _TS_RE.match(added)
                            or added < cold_start_from):
                        continue
                yield rid, row

        taken, last_id, eligible = take_after_cursor(candidates(), self._MAX_ROWS_PER_SYNC)

        if cursor is None:
            logger.warning(
                "urlhaus_cold_start",
                lookback_days=self._COLD_START_LOOKBACK.days,
                rows_in_file=dated,
                rows_older_than_lookback_skipped=dated - eligible,
            )
        if eligible > len(taken):
            logger.warning(
                "urlhaus_backlog_capped",
                eligible=eligible, taken=len(taken), remaining=eligible - len(taken),
            )
        return taken, last_id

    def _rows_to_iocs(self, rows: List[List[str]]) -> List[Dict[str, Any]]:
        """Build IOC dicts. Tags field holds the literal "None" when empty."""
        iocs: List[Dict[str, Any]] = []
        seen: set = set()
        for raw in rows:
            try:
                row = dict(zip(_CSV_FIELDNAMES, raw))
                url_value = (row.get("url") or "").strip()
                url_status = (row.get("url_status") or "").strip()
                threat = (row.get("threat") or "").strip()
                tags_str = (row.get("tags") or "").strip()
                last_online = (row.get("last_online") or "").strip()
                reporter = (row.get("reporter") or "").strip()

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
                    tags.extend(
                        t.strip().lower() for t in tags_str.split(",")
                        if t.strip() and t.strip() != "None"
                    )

                iocs.append(self._make_ioc(
                    ioc_type="url",
                    value=url_value,
                    tags=list(dict.fromkeys(tags)),
                    threat_score=score,
                    confidence=70,
                    metadata={
                        "status": url_status,
                        "threat": threat,
                        "reporter": reporter,
                        "source": "urlhaus",
                    },
                    mitre_techniques=[],
                    first_seen=_parse_ts(row.get("dateadded")),
                    last_seen=_parse_ts(last_online) if last_online else None,
                ))
            except Exception:
                continue
        return iocs


# ── module-level helpers ─────────────────────────────────────────────────────

def _data_rows(text: str):
    """Yield parsed CSV rows, skipping the # comment block. Lazy: no line list."""
    for row in csv.reader(iter_lines(text), skipinitialspace=True):
        if not row or row[0].startswith("#"):
            continue
        yield row


def _parse_ts(value: Optional[str]) -> Optional[datetime]:
    """URLhaus timestamp -> UTC-aware datetime, or None.

    "2026-04-06 14:15:12" (export) or "2026-04-06 14:15:12 UTC" (some API responses).
    """
    if not value:
        return None
    clean = value.strip().replace(" UTC", "")
    try:
        return datetime.strptime(clean, _TS_FMT).replace(tzinfo=timezone.utc)
    except (ValueError, AttributeError):
        return None
