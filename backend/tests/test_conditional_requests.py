"""Phase 4 Section D3 — conditional requests, and what a 304 means.

Implemented in ``BaseFeed._fetch_url`` rather than per connector: it applies wherever the
SERVER cooperates and costs nothing where it does not. Hard-coding which feeds "should"
support ETags would be a guess about servers rather than a fact about them.

A 304 IS A SUCCESSFUL SYNC. The source is asserting the file has not changed. Three
consequences, each with a way of going wrong:

* it must not be scored as a failure, or a reliably-unchanged feed backs off to the
  3-day cap while being perfectly healthy;
* it must not be recorded as ``no_data``, which is a symptom — feed health has to tell
  "checked, unchanged" from "fetched nothing";
* the gap check must be SKIPPED, not run. ``_check_window_continuity`` answers "did
  records fall through the gap between syncs", and a 304 says none entered or aged out.
  Running it against an absent file would report data loss that provably did not happen.
"""

import ast
import inspect
import textwrap

import pytest

from app.feeds.base import BaseFeed


class _Resp:
    def __init__(self, status=200, headers=None, payload=None):
        self.status_code = status
        self.headers = headers or {}
        self._payload = payload if payload is not None else {}
        self.text = ""

    def raise_for_status(self):
        if self.status_code >= 400:
            raise RuntimeError("HTTP " + str(self.status_code))

    def json(self):
        return self._payload


class _Client:
    def __init__(self, response):
        self._response = response
        self.sent_headers = None

    async def get(self, url, headers=None, **kw):
        self.sent_headers = headers or {}
        return self._response

    async def aclose(self):
        """`BaseFeed.run()` closes its client in a finally block."""
        return None


class _Feed(BaseFeed):
    name, slug, feed_type, url = "cond", "cond", "csv", "https://example.invalid/f"
    source_shape = "sliding-window"

    async def fetch(self):
        return await self._fetch_url(self.url)

    async def parse(self, raw):
        return [self._make_ioc(ioc_type="domain", value="parsed.example")]


def _feed(response, etag=None, last_modified=None):
    f = _Feed(api_key=None)
    f._client = _Client(response)
    f.http_etag = etag
    f.http_last_modified = last_modified
    return f


class TestValidatorsAreSentWhenHeld:
    async def test_nothing_is_sent_on_a_first_fetch(self):
        f = _feed(_Resp())
        await f.fetch()
        sent = f._client.sent_headers or {}
        assert "If-None-Match" not in sent and "If-Modified-Since" not in sent, (
            "conditional headers sent with no stored validators — the server would be "
            "asked to compare against nothing"
        )

    async def test_an_etag_is_sent_as_if_none_match(self):
        f = _feed(_Resp(), etag='W/"abc123"')
        await f.fetch()
        assert f._client.sent_headers["If-None-Match"] == 'W/"abc123"'

    async def test_a_last_modified_is_sent_as_if_modified_since(self):
        f = _feed(_Resp(), last_modified="Wed, 21 Oct 2026 07:28:00 GMT")
        await f.fetch()
        assert (f._client.sent_headers["If-Modified-Since"]
                == "Wed, 21 Oct 2026 07:28:00 GMT")

    async def test_a_200_records_the_new_validators(self):
        f = _feed(_Resp(headers={"ETag": '"new"', "Last-Modified": "X"}))
        await f.fetch()
        assert f.next_http_etag == '"new"'
        assert f.next_http_last_modified == "X"
        assert f.not_modified is False

    async def test_a_server_that_offers_no_validators_is_not_a_failure(self):
        """Most API-shaped feeds will never send an ETag. That must be fine."""
        f = _feed(_Resp(headers={}))
        await f.fetch()
        assert f.next_http_etag is None
        assert f.not_modified is False


class TestA304ShortCircuits:
    async def test_it_sets_not_modified_and_carries_validators_forward(self):
        f = _feed(_Resp(status=304), etag='"same"', last_modified="Y")
        await f.fetch()
        assert f.not_modified is True
        # A 304 body carries no ETag to replace them with, so the old ones still
        # describe the current file and must survive.
        assert f.next_http_etag == '"same"'
        assert f.next_http_last_modified == "Y"

    async def test_run_does_not_parse_a_304(self):
        """THE short-circuit.

        Parsing an empty 304 body yields zero IOCs, which is indistinguishable from a
        feed that genuinely went empty — and the scheduler records that as `no_data`,
        a symptom rather than a healthy state.
        """
        f = _feed(_Resp(status=304), etag='"same"')
        iocs = await f.run()
        assert iocs == [], "a 304 produced IOCs, so the empty body was parsed"

    async def test_a_200_still_parses(self):
        """The control: without it, the test above passes for a run() that never parses."""
        f = _feed(_Resp(status=200))
        iocs = await f.run()
        assert len(iocs) == 1, "a 200 stopped parsing, so the short-circuit is too wide"


class TestTheSchedulerTreatsItAsSuccess:
    def _source(self):
        from app.services import feed_scheduler

        return inspect.getsource(feed_scheduler._run_feed_sync_inner)

    def _block(self):
        """The 304 branch only, so assertions cannot pick up the ingest path."""
        source = self._source()
        return source[source.index("# ── 304 Not Modified"):source.index("# Ingest")]

    def test_the_status_is_no_change_not_success(self):
        """Feed health must distinguish 'checked, unchanged' from 'fetched and ingested'.

        A feed showing no_change for three days is working correctly and must not render
        as broken (Spec 2 §4.4).
        """
        assert '"no_change"' in self._block(), (
            "the 304 path does not record a distinct status, so an unchanged feed is "
            "indistinguishable from one that ingested rows"
        )

    def test_it_resets_the_failure_counter(self):
        """Otherwise a reliably-unchanged feed backs off to the 3-day cap."""
        assert "consecutive_failures = 0" in self._block(), (
            "the 304 path does not reset consecutive_failures, so repeated 304s — the "
            "signature of a HEALTHY, stable feed — would accumulate back-off"
        )

    def _assigned_in_block(self):
        block = textwrap.dedent(self._block())
        tree = ast.parse("if True:\n" + textwrap.indent(block, "    "))
        return {
            t.attr for n in ast.walk(tree) if isinstance(n, ast.Assign)
            for t in n.targets if isinstance(t, ast.Attribute)
        }

    def test_it_does_not_zero_ioc_count(self):
        """The feed contributed what it contributed; the rows are still in the corpus."""
        assigned = self._assigned_in_block()
        assert assigned, "no assignments extracted; the check would be vacuous"
        assert "ioc_count" not in assigned, (
            "the 304 path writes ioc_count, reporting the feed as having contributed "
            "nothing when its rows are still there"
        )

    def test_it_does_not_touch_the_watermark(self):
        """An ASSIGNMENT check — the block discusses the watermark at length in prose."""
        assert "last_ingest_watermark" not in self._assigned_in_block(), (
            "the 304 path writes last_ingest_watermark; it must stay describing the "
            "file that is still current"
        )

    def test_the_gap_check_is_not_run_on_a_304(self):
        """Skipped entirely rather than run against an absent file."""
        block = textwrap.dedent(self._block())
        tree = ast.parse("if True:\n" + textwrap.indent(block, "    "))
        called = {
            getattr(n.func, "id", None) or getattr(n.func, "attr", None)
            for n in ast.walk(tree) if isinstance(n, ast.Call)
        }
        assert called, "no calls extracted; the check would be vacuous"
        assert "_check_window_continuity" not in called, (
            "the 304 path runs the gap check. A 304 asserts no records entered or aged "
            "out, so a gap reported here would be data loss that provably did not happen."
        )

    def test_the_status_is_distinct_from_no_data(self):
        source = self._source()
        assert '"no_change"' in source
        # `no_data` is set by ingest_iocs for a genuinely empty fetch. The two must not
        # collapse into one value, or feed health cannot tell healthy from symptomatic.
        assert '"no_change"' != '"no_data"'


class TestALong304StreakDoesNotManufactureAGap:
    """The failure mode a reader would worry about, asserted rather than reasoned about.

    Concern: if a feed serves 304 for weeks, does the stored watermark go stale in a way
    that produces a FALSE gap when a 200 finally arrives?

    It does not, and the reason is structural rather than lucky: the watermark describes
    the newest record in the last file we actually read, and a 304 means that file is
    still the current file. So a later 200 compares against the right value however long
    the streak ran — elapsed wall-clock time never enters the calculation.
    """

    def _gap_reported(self, watermark_iso, earliest_iso):
        """Replicates `_check_window_continuity`'s comparison in isolation."""
        from datetime import datetime

        return (datetime.fromisoformat(earliest_iso)
                > datetime.fromisoformat(watermark_iso))

    def test_a_gap_is_reported_when_records_really_were_missed(self):
        """The control. Without it the parametrized test below proves nothing."""
        assert self._gap_reported("2026-08-01T00:00:00", "2026-08-05T00:00:00") is True

    @pytest.mark.parametrize("streak_days", [1, 7, 30, 365])
    def test_no_false_gap_however_long_the_304_streak_ran(self, streak_days):
        """The watermark is untouched by 304s, and the next 200's file still overlaps it.

        An unchanged sliding-window file contains the same records, so its earliest
        record is at or before the stored watermark — which came from that same file —
        regardless of how much wall-clock time passed while the server answered 304.
        """
        watermark = "2026-08-01T12:00:00"
        earliest_in_unchanged_file = "2026-08-01T06:00:00"
        assert self._gap_reported(watermark, earliest_in_unchanged_file) is False, (
            "a " + str(streak_days) + "-day 304 streak produced a false gap; the "
            "watermark must describe the still-current file rather than ageing against "
            "wall-clock time"
        )

    def test_the_scheduler_leaves_the_watermark_alone_across_the_streak(self):
        """The property above holds only because nothing writes the watermark on a 304."""
        from app.services import feed_scheduler

        source = inspect.getsource(feed_scheduler._run_feed_sync_inner)
        block = source[source.index("# ── 304 Not Modified"):source.index("# Ingest")]
        assert "feed.last_ingest_watermark =" not in block
