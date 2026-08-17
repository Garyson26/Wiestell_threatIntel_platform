"""Phase 4 Section D1/D2 — the OTX incremental cursor.

`modified_since` used to be a fixed ``now - 7 days`` recomputed on every sync. That is a
WINDOW, not a cursor, and it fails in both directions at once: it re-fetches a week of
pulses every run, and anything modified more than seven days before a sync that did not
happen is lost — an outage longer than a week is silent data loss.

THE ONE INVARIANT THESE TESTS EXIST FOR: **the cursor advances only after a complete
walk.** A partial fetch that advanced it would skip everything it failed to retrieve,
permanently, while the sync still reported success. Re-fetching costs a duplicate page and
nothing else, because ingestion is ``INSERT ... IGNORE`` behind the re-read gate. So the
contract is at-least-once and never at-most-once.

That shape is also what keeps intra-feed checkpointing addable later. If the Phase 6
latency measurement shows a sync cannot finish inside Render's idle window, checkpointing
changes only *when* the cursor is written — not what it means, not who reads it, and not
the safety property above.
"""

import inspect
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, List, Optional

import pytest

from app.feeds.otx_alienvault import OTXAlienVaultFeed


class _FakeResponse:
    def __init__(self, payload):
        self._payload = payload

    def raise_for_status(self):
        return None

    def json(self):
        return self._payload


class _FakeClient:
    """Serves a scripted page sequence and records the params it was called with."""

    def __init__(self, pages: List[Any]):
        self._pages = list(pages)
        self.calls: List[Dict[str, Any]] = []

    async def get(self, url, headers=None, params=None):
        # A REAL DELAY, so "start time" and "finish time" are distinguishable. Without
        # it the walk completes in microseconds and a finish-time cursor is
        # indistinguishable from a start-time one — measured: the mutation swapping
        # started_at for now() failed ZERO tests until this sleep existed.
        import asyncio

        await asyncio.sleep(0.05)
        self.calls.append({"url": url, "params": params})
        page = self._pages.pop(0)
        if isinstance(page, Exception):
            raise page
        return _FakeResponse(page)


def _feed(pages, cursor: Optional[str] = None):
    # Short and obviously fake: OTX's fetch() raises without SOME key, and the
# value is never used. Kept under the pre-commit secret scan's 8-character
# threshold so a real leak is not lost among fixture noise.
    feed = OTXAlienVaultFeed(api_key="x")
    feed.sync_cursor = cursor
    feed._client = _FakeClient(pages)
    return feed


def _page(results, next_url=None):
    return {"results": results, "next": next_url}


class TestTheCursorIsUsedAsModifiedSince:
    async def test_a_stored_cursor_is_sent_verbatim(self):
        feed = _feed([_page([])], cursor="2026-08-01T00:00:00.000000")
        await feed.fetch()
        params = feed._client.calls[0]["params"]
        assert params["modified_since"] == "2026-08-01T00:00:00.000000", (
            "the stored cursor was not used, so the sync re-fetches a fixed window "
            "instead of resuming"
        )

    async def test_no_cursor_bootstraps_to_seven_days(self):
        """First run, or a cleared column. Bounded rather than all-of-history."""
        feed = _feed([_page([])], cursor=None)
        await feed.fetch()
        sent = feed._client.calls[0]["params"]["modified_since"]
        parsed = datetime.strptime(sent, "%Y-%m-%dT%H:%M:%S.%f")
        age = datetime.utcnow() - parsed
        assert timedelta(days=6, hours=20) < age < timedelta(days=7, hours=4), (
            f"bootstrap window is {age}, expected ~7 days. Fetching all of OTX history "
            "on a first sync would not finish inside Render's idle window."
        )


class TestTheCursorAdvancesOnlyOnACompleteWalk:
    async def test_a_complete_walk_sets_next_cursor(self):
        feed = _feed([_page([{"id": 1}], next_url="page2"), _page([{"id": 2}])])
        await feed.fetch()
        assert feed.next_cursor is not None

    async def test_the_cursor_is_the_start_time_not_the_finish_time(self):
        """Anything modified DURING the walk must be re-fetched, not skipped.

        Same reasoning as the Section A cadence fix: take the timestamp before the work.
        A finish-time cursor would silently skip every pulse modified while the pages
        were being walked.
        """
        before = datetime.now(timezone.utc)
        # Three pages x 50 ms, so a finish-time cursor lands ~150 ms after the start.
        feed = _feed([
            _page([{"id": 1}], next_url="p2"),
            _page([{"id": 2}], next_url="p3"),
            _page([{"id": 3}]),
        ])
        await feed.fetch()
        after = datetime.now(timezone.utc)

        cursor = datetime.strptime(feed.next_cursor, "%Y-%m-%dT%H:%M:%S.%f").replace(
            tzinfo=timezone.utc
        )
        assert before <= cursor <= after
        # And specifically at the START: allow a tiny epsilon for clock resolution.
        elapsed = (after - before).total_seconds()
        assert elapsed > 0.1, (
            f"the walk took {elapsed:.3f}s; too fast to distinguish start from finish, "
            "so this assertion would pass either way"
        )
        assert (cursor - before).total_seconds() < elapsed / 2, (
            "the cursor looks like a finish time. Pulses modified during the walk "
            "would be skipped on the next sync."
        )

    async def test_a_failed_page_leaves_the_cursor_unset(self):
        """THE test. A partial walk must not advance."""
        feed = _feed([
            _page([{"id": 1}], next_url="page2"),
            RuntimeError("connection reset mid-walk"),
        ])
        result = await feed.fetch()

        assert result["results"], "the partial results should still be returned"
        assert feed.next_cursor is None, (
            "the cursor advanced after a FAILED page walk. Everything the failed and "
            "subsequent pages would have returned is now skipped permanently, and the "
            "sync reports success. This is the defect the whole design prevents."
        )

    async def test_hitting_the_page_cap_also_leaves_the_cursor_unset(self):
        """A backlog larger than the cap is not the same as being finished.

        With the cap treated as success, a large backlog would be skipped one cap's
        worth per sync while every sync reported success — slower than the failure case
        but the same silent loss.
        """
        from app.feeds import otx_alienvault

        pages = [_page([{"id": i}], next_url=f"page{i + 1}")
                 for i in range(otx_alienvault._MAX_PAGES)]
        feed = _feed(pages)
        await feed.fetch()
        assert feed.next_cursor is None, (
            "the cursor advanced despite the walk stopping at the page cap with more "
            "pages outstanding"
        )

    async def test_a_walk_that_ends_naturally_at_the_cap_does_advance(self):
        """The boundary. Last page has no `next`, so the cap was not truncating."""
        from app.feeds import otx_alienvault

        pages = [_page([{"id": i}], next_url=f"page{i + 1}")
                 for i in range(otx_alienvault._MAX_PAGES - 1)]
        pages.append(_page([{"id": 999}], next_url=None))
        feed = _feed(pages)
        await feed.fetch()
        assert feed.next_cursor is not None, (
            "a walk that reached the last page exactly at the cap was treated as "
            "truncated, so this feed would never advance its cursor again"
        )


class TestTheSchedulerPersistsItCorrectly:
    """Source-level: the write must be conditional and inside the success path."""

    def _source(self):
        from app.services import feed_scheduler

        return inspect.getsource(feed_scheduler._run_feed_sync_inner)

    def test_the_cursor_is_loaded_before_the_fetch(self):
        source = self._source()
        load = source.index("stored_cursor = feed.sync_cursor")
        hand_off = source.index("connector.sync_cursor = stored_cursor")
        run = source.index("await connector.run()")
        assert load < hand_off < run

    def test_the_cursor_is_written_only_on_success(self):
        """Guarded by `if new_cursor:`, inside the block that also clears the error."""
        source = self._source()
        assert "if new_cursor:" in source, (
            "the cursor is written unconditionally, so a partial walk (which leaves "
            "next_cursor None) would blank the stored cursor and restart from the "
            "bootstrap window"
        )
        write = source.index("feed.sync_cursor = new_cursor")
        success_marker = source.index("feed.consecutive_failures = 0")
        assert write > success_marker, (
            "the cursor is written outside the success path, so it could advance for a "
            "sync whose ingest failed"
        )

    def test_no_failure_path_writes_the_cursor(self):
        """AST, not substring — the comments discuss sync_cursor at length."""
        import ast
        import textwrap

        from app.services import feed_scheduler

        for name in ("_mark_failed",):
            tree = ast.parse(textwrap.dedent(
                inspect.getsource(getattr(feed_scheduler, name))
            ))
            assigned = {
                t.attr for n in ast.walk(tree) if isinstance(n, ast.Assign)
                for t in n.targets if isinstance(t, ast.Attribute)
            }
            assert "sync_cursor" not in assigned, (
                f"{name} advances the cursor on a failure"
            )


class TestOTXIsDeclaredIncremental:
    def test_the_shape_matches_the_mechanism(self):
        """The cursor is *why* INCREMENTAL needs no gap monitoring."""
        from app.feeds.base import SHAPE_INCREMENTAL

        assert OTXAlienVaultFeed.source_shape == SHAPE_INCREMENTAL
        assert OTXAlienVaultFeed.__new__(OTXAlienVaultFeed).rolling_window is False, (
            "OTX would be gap-monitored, but the cursor already guarantees continuity — "
            "the watermark check would compare timestamps of a delta stream and report "
            "spurious gaps"
        )
