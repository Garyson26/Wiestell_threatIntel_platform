"""abuse.ch keyed exports (issue #104).

abuse.ch withdrew its keyless CSV exports (410 Gone, observed 2026-11-11). Every
remaining export puts the Auth-Key in the URL *path*, so these tests cover three
things that move with that: the key never leaks through an error string, a missing
key fails loudly instead of ingesting nothing, and each connector parses the file
abuse.ch actually serves today.
"""

import asyncio

import httpx
import pytest

_KEY = "0123456789abcdef0123456789abcdef0123456789abcdef"  # 48 chars, like a real key

_EXPORT_HOSTS = ("urlhaus-api.abuse.ch", "threatfox-api.abuse.ch", "mb-api.abuse.ch")


def _status_error(url: str, status: int = 404) -> httpx.HTTPStatusError:
    """A real httpx error, so the message format is httpx's own, not a guess at it."""
    request = httpx.Request("GET", url)
    response = httpx.Response(status, request=request)
    try:
        response.raise_for_status()
    except httpx.HTTPStatusError as exc:
        return exc
    raise AssertionError("raise_for_status did not raise")


class TestKeyInPathIsRedacted:
    """The key is a path segment, and httpx puts the full URL in its exception text.

    Shape-based redaction covers keys this process has never been configured with,
    which value-based redaction cannot.
    """

    @pytest.mark.parametrize("host", _EXPORT_HOSTS)
    def test_httpx_error_for_each_export_host_is_redacted(self, host):
        from app.utils.sanitize import redact_secrets

        exc = _status_error(f"https://{host}/v2/files/exports/{_KEY}/recent.csv")
        assert _KEY in str(exc), "precondition: httpx embeds the URL in the message"

        redacted = redact_secrets(exc)
        assert _KEY not in redacted
        assert f"https://{host}/v2/files/exports/***REDACTED***/recent.csv" in redacted

    def test_indicator_urls_are_not_mangled(self):
        """The pattern is anchored on abuse.ch; an IOC with /exports/ must survive."""
        from app.utils.sanitize import redact_secrets

        ioc = "http://evil.example/v2/files/exports/payload-archive/run.exe"
        assert redact_secrets(ioc) == ioc

    def test_the_advertised_url_placeholder_is_not_redacted(self):
        """`{KEY}` is shorter than the 8-char floor, so the served url stays readable."""
        from app.feeds.malwarebazaar import MalwareBazaarFeed
        from app.utils.sanitize import redact_secrets

        assert "{KEY}" in MalwareBazaarFeed.url
        assert redact_secrets(MalwareBazaarFeed.url) == MalwareBazaarFeed.url


class TestErrorText:
    def test_blank_transport_errors_fall_back_to_the_class_name(self):
        from app.feeds.base import error_text

        assert str(httpx.ReadTimeout("")) == ""  # the failure mode being guarded
        assert error_text(httpx.ReadTimeout("")) == "ReadTimeout"

    def test_a_real_message_is_kept(self):
        from app.feeds.base import error_text

        assert error_text(ValueError("bad row")) == "bad row"


# ── fail loudly ──────────────────────────────────────────────────────────────

def _connectors():
    from app.feeds.malwarebazaar import MalwareBazaarFeed
    from app.feeds.threatfox import ThreatFoxFeed
    from app.feeds.urlhaus import URLhausFeed

    return [
        (URLhausFeed, "URLHAUS_API_KEY"),
        (MalwareBazaarFeed, "MALWAREBAZAAR_API_KEY"),
        (ThreatFoxFeed, "THREATFOX_API_KEY"),
    ]


_CONNECTOR_INDEXES = [0, 1, 2]


def test_the_connector_list_covers_all_three_abusech_feeds():
    """The parametrized tests below index into _connectors(); a short list is a gap."""
    assert len(_connectors()) == len(_CONNECTOR_INDEXES) == 3


class TestMissingKeyFailsLoudly:
    """An unconfigured feed must record `failed` with the reason, not `no_data`.

    The keyless fallback these connectors used to take now leads to a 410, so
    "degrade gracefully without a key" had become "ingest nothing and report
    success".
    """

    @pytest.mark.parametrize("index", _CONNECTOR_INDEXES)
    def test_fetch_without_a_key_raises_naming_the_setting(self, index):
        from app.feeds.base import FeedConfigurationError

        connector, env_name = _connectors()[index]
        with pytest.raises(FeedConfigurationError) as info:
            asyncio.run(connector(api_key=None).fetch())
        # Leads with the cause: this string is what the admin panel shows, often
        # truncated, so the missing setting has to come first.
        assert str(info.value).startswith(f"{env_name} is not set")

    @pytest.mark.parametrize("index", _CONNECTOR_INDEXES)
    def test_every_abusech_connector_declares_the_key_required(self, index):
        connector, env_name = _connectors()[index]
        assert connector.requires_api_key is True
        assert connector.api_key_env == env_name


class TestFailedDownloadRaisesWithTheKeyRedacted:
    """The backbone export is no longer wrapped in try/except-return-empty."""

    @pytest.mark.parametrize("index", _CONNECTOR_INDEXES)
    @pytest.mark.parametrize("status", [404, 410])
    def test_http_error_propagates_without_the_key(self, index, status):
        connector, _ = _connectors()[index]

        def handler(request):
            return httpx.Response(status, request=request)

        feed = connector(api_key=_KEY)
        feed._client = httpx.AsyncClient(transport=httpx.MockTransport(handler))
        with pytest.raises(RuntimeError) as info:
            asyncio.run(feed.fetch())
        message = str(info.value)
        assert str(status) in message
        assert _KEY not in message, "the key travels in the URL path and must be redacted"


# ── URLhaus id cursor ────────────────────────────────────────────────────────

def _urlhaus_csv(rows):
    """rows: [(id, 'YYYY-MM-DD HH:MM:SS')], written newest-first like the real file."""
    head = (
        "################################################################\n"
        "# abuse.ch URLhaus Database Dump (CSV - recent URLs only)      #\n"
        "################################################################\n"
        "#\n"
        "# id,dateadded,url,url_status,last_online,threat,tags,urlhaus_link,reporter\n"
    )
    body = "".join(
        f'"{i}","{ts}","http://evil.example/{i}","online","{ts}","malware_download",'
        f'"None","https://urlhaus.abuse.ch/url/{i}/","r"\n'
        for i, ts in sorted(rows, reverse=True)
    )
    return head + body


def _sync(cursor, text, cap=None, monkeypatch=None):
    from app.feeds.urlhaus import URLhausFeed

    if cap is not None:
        monkeypatch.setattr(URLhausFeed, "_MAX_ROWS_PER_SYNC", cap)
    feed = URLhausFeed(api_key=_KEY)
    feed.sync_cursor = cursor
    iocs = asyncio.run(feed.parse({"recent_csv": text}))
    return [int(i["value"].rsplit("/", 1)[1]) for i in iocs], feed.next_cursor


class TestURLhausIdCursor:
    def test_only_rows_above_the_cursor_are_ingested(self):
        text = _urlhaus_csv([(i, f"2026-11-1{i % 2} 0{i}:00:00") for i in range(1, 8)])
        ids, nxt = _sync("4", text)
        assert sorted(ids) == [5, 6, 7]
        assert nxt == "7"

    def test_nothing_new_leaves_the_cursor_unset(self):
        """None means 'do not write', so the stored cursor survives an empty sync."""
        text = _urlhaus_csv([(1, "2026-11-10 00:00:00"), (2, "2026-11-10 01:00:00")])
        ids, nxt = _sync("2", text)
        assert ids == [] and nxt is None

    def test_a_backlog_larger_than_the_cap_drains_without_loss(self, monkeypatch):
        """Oldest-first: three capped syncs cover all 25 rows, none twice, none skipped."""
        rows = [(i, "2026-11-10 %02d:%02d:00" % (i // 60, i % 60)) for i in range(1, 26)]
        text = _urlhaus_csv(rows)
        seen, cursor = [], "0"
        for _ in range(3):
            ids, cursor = _sync(cursor, text, cap=10, monkeypatch=monkeypatch)
            seen.extend(ids)
        assert sorted(seen) == list(range(1, 26))
        assert len(seen) == len(set(seen))

    def test_a_cursor_older_than_the_file_is_still_capped(self, monkeypatch):
        """The memory guard: a stale cursor must not turn into a full read."""
        rows = [(i, "2026-11-10 %02d:%02d:00" % (i // 60, i % 60)) for i in range(100, 200)]
        ids, nxt = _sync("1", _urlhaus_csv(rows), cap=10, monkeypatch=monkeypatch)
        assert sorted(ids) == list(range(100, 110))
        assert nxt == "109"

    def test_cold_start_reads_only_the_lookback_from_the_newest_row(self):
        from app.feeds.urlhaus import URLhausFeed

        assert URLhausFeed._COLD_START_LOOKBACK.days == 7
        rows = [(1, "2026-10-01 00:00:00"), (2, "2026-11-03 23:59:59"),
                (3, "2026-11-04 00:00:01"), (4, "2026-11-11 00:00:00")]
        ids, nxt = _sync(None, _urlhaus_csv(rows))
        assert sorted(ids) == [3, 4]
        assert nxt == "4"

    def test_an_unreadable_cursor_falls_back_to_a_cold_start(self):
        rows = [(1, "2026-10-01 00:00:00"), (4, "2026-11-11 00:00:00")]
        ids, _ = _sync("not-an-id", _urlhaus_csv(rows))
        assert ids == [4]


# ── MalwareBazaar: the keyed file reaches the right parser ───────────────────

class TestMalwareBazaarKeyedFileIsParsed:
    def test_parse_routes_the_keyed_recent_csv_to_the_commented_header_parser(self):
        """Through parse(), not the parser method: the bug was in the ROUTING.

        Until 2026-11-11 the keyed recent.csv went to a parser that took the first
        non-# line as the header. Measured on the live file: 0 IOCs from 1,474 rows.
        The correct parser existed in the same module and was only ever pointed at
        the keyless file.
        """
        from tests.test_feeds import _MB_RECENT_CSV

        from app.feeds.malwarebazaar import MalwareBazaarFeed

        feed = MalwareBazaarFeed(api_key=_KEY)
        iocs = asyncio.run(feed.parse({"recent_csv": _MB_RECENT_CSV, "api": {}, "cscb_csv": ""}))
        assert len(iocs) == 6, "two samples x three hash types"
        assert feed.observed_window is not None


# ── ThreatFox id cursor ──────────────────────────────────────────────────────

def _threatfox_csv(rows):
    """rows: [(id, first_seen, last_seen)]; 15 fields, newest-first like the real file.

    last_seen is "" for an IOC never re-sighted. The real file is the union of IOCs
    added in the last ~48 h and older IOCs re-sighted recently; the second set is the
    one with last_seen set and an old first_seen.
    """
    head = (
        "################################################################\n"
        "# ThreatFox IOCs: recent additions - CSV format                #\n"
        "################################################################\n"
        "#\n"
        '# "first_seen_utc","ioc_id","ioc_value","ioc_type","threat_type","fk_malware",'
        '"malware_alias","malware_printable","last_seen_utc","confidence_level",'
        '"is_compromised","reference","tags","anonymous","reporter"\n'
    )
    body = "".join(
        f'"{fs}", "{i}", "c2-{i}.example", "domain", "botnet_cc", "win.x", "None", '
        f'"X", "{ls}", "75", "False", "None", "None", "0", "r"\n'
        for i, fs, ls in sorted(rows, key=lambda r: r[1], reverse=True)
    )
    return head + body


def _now_ts(hours_ago=0.0):
    from datetime import datetime, timedelta, timezone

    return (datetime.now(timezone.utc) - timedelta(hours=hours_ago)).strftime(
        "%Y-%m-%d %H:%M:%S")


def _tf_sync(cursor, text, cap=None, monkeypatch=None):
    from app.feeds.threatfox import ThreatFoxFeed

    if cap is not None:
        monkeypatch.setattr(ThreatFoxFeed, "_MAX_ROWS_PER_SYNC", cap)
    feed = ThreatFoxFeed(api_key=_KEY)
    feed.sync_cursor = cursor
    iocs = asyncio.run(feed.parse({"recent_csv": text}))
    ids = [int(i["value"].split("-")[1].split(".")[0]) for i in iocs]
    return ids, feed.next_cursor, feed


class TestThreatFoxIdCursor:
    def test_only_ids_above_the_cursor_are_ingested(self):
        text = _threatfox_csv([(i, _now_ts(10 - i), "") for i in range(1, 8)])
        ids, nxt, _ = _tf_sync("4", text)
        assert sorted(ids) == [5, 6, 7]
        assert nxt == "7"

    def test_a_resighted_old_ioc_is_not_re_read(self):
        """Measured 2026-11-11: 52 rows re-entered the file in six hours with old ids.

        They are re-sightings of IOCs first seen months earlier. The cursor leaves
        them alone; re-reading them is what costs a round-trip UPDATE each and a
        sighting_count increment (#105).
        """
        text = _threatfox_csv([
            (100, _now_ts(24 * 60), _now_ts(1)),   # first seen 60 days ago, re-sighted
            (500, _now_ts(2), ""),                 # a genuine addition
        ])
        ids, nxt, _ = _tf_sync("400", text)
        assert ids == [500]
        assert nxt == "500"

    def test_ids_not_monotonic_in_first_seen_still_follow_the_id(self):
        """178 id/first_seen inversions on the real file: the cursor is the id."""
        text = _threatfox_csv([(10, _now_ts(1), ""), (11, _now_ts(5), "")])
        ids, nxt, _ = _tf_sync("10", text)
        assert ids == [11] and nxt == "11"

    def test_nothing_new_leaves_the_cursor_unset(self):
        text = _threatfox_csv([(1, _now_ts(3), ""), (2, _now_ts(2), "")])
        ids, nxt, _ = _tf_sync("2", text)
        assert ids == [] and nxt is None

    def test_a_backlog_larger_than_the_cap_drains_without_loss(self, monkeypatch):
        text = _threatfox_csv([(i, _now_ts(30 - i), "") for i in range(1, 26)])
        seen, cursor = [], "0"
        for _ in range(3):
            ids, cursor, _ = _tf_sync(cursor, text, cap=10, monkeypatch=monkeypatch)
            seen.extend(ids)
        assert sorted(seen) == list(range(1, 26))
        assert len(seen) == len(set(seen))

    def test_cold_start_takes_the_additions_window_not_the_resighting_tail(self):
        from app.feeds.threatfox import ThreatFoxFeed

        assert ThreatFoxFeed._COLD_START_LOOKBACK.total_seconds() == 48 * 3600
        text = _threatfox_csv([
            (1, _now_ts(24 * 90), _now_ts(1)),     # re-sighted, first seen 90 days ago
            (2, _now_ts(49), _now_ts(2)),          # just outside the window
            (3, _now_ts(47), ""),                  # inside
            (4, _now_ts(0.5), ""),                 # newest
        ])
        ids, nxt, _ = _tf_sync(None, text)
        assert sorted(ids) == [3, 4]
        assert nxt == "4"

    def test_window_starts_at_the_oldest_row_never_resighted(self):
        """The continuity check needs the ADDITIONS window, not the re-sighting tail.

        A re-sighted row's first_seen reaches back months. Using it as the window
        start would put the start before any plausible previous watermark, so the
        check could never report a gap -- which is what the old 4237 h figure did.
        """
        from datetime import timedelta

        oldest_addition = _now_ts(48)
        text = _threatfox_csv([
            (1, _now_ts(24 * 120), _now_ts(1)),
            (2, oldest_addition, ""),
            (3, _now_ts(0.25), ""),
        ])
        _, _, feed = _tf_sync("3", text)
        lo, hi = feed.observed_window
        assert lo.strftime("%Y-%m-%d %H:%M:%S") == oldest_addition
        assert hi - lo < timedelta(hours=49)

    def test_a_file_with_no_unsighted_rows_records_no_window(self):
        """No evidence either way is None, never a window built from the tail."""
        text = _threatfox_csv([(1, _now_ts(24 * 30), _now_ts(1))])
        _, _, feed = _tf_sync("0", text)
        assert feed.observed_window is None

    def test_literal_none_tags_are_not_emitted(self):
        """668 of 8,064 real rows carry the string "None" in the tags column."""
        text = _threatfox_csv([(1, _now_ts(1), "")])
        from app.feeds.threatfox import ThreatFoxFeed

        feed = ThreatFoxFeed(api_key=_KEY)
        feed.sync_cursor = "0"
        (ioc,) = asyncio.run(feed.parse({"recent_csv": text}))
        assert "none" not in ioc["tags"]
        assert ioc["type"] == "domain"
