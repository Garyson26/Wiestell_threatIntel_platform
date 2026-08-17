"""Phase 4 Section A — the cadence fix, and the two-timestamp split.

THE DEFECT. Next-due was computed from ``last_sync_at``, which is stamped when a sync
*finishes*. So each interval was really ``sync_frequency + sync_duration``, and the error
accumulated: a feed configured for 6h against a 6h cron is always a few minutes short of
due when the tick arrives, so it fires every *other* tick — 12h actual for a 6h setting.

THE FIX (design notes §1.3). Capture the timestamp before ``connector.run()`` and schedule
from that. With a zero effective offset the intervals become exact for every value,
including ``sync_frequency == cron_interval``.

THE SPLIT (§1.3.1). ``last_sync_at`` could not simply be re-stamped earlier, because
``dashboard/feed-health`` reads it as "last successful ingest". A second column resolves
both jobs at once, and buys a third property neither had: ``last_attempt_at`` advancing
while ``last_sync_at`` stands still is exactly "broken, not idle" — a permanently failing
feed used to look healthy, because the failure path stamped ``last_sync_at`` too.

These are pure-arithmetic simulations of the tick, so they need no database.
"""

import ast
import inspect
from datetime import datetime, timedelta

import pytest

HOUR = 3600


def _simulate(sync_frequency, cron_interval, *, schedule_from, sync_duration, ticks=40):
    """Replay the tick loop and return the hours at which the feed actually syncs.

    ``schedule_from`` is "start" (the fix) or "completion" (the defect), and is the only
    difference between the two arms.
    """
    now = datetime(2026, 1, 1)
    last = None
    fired = []
    for i in range(ticks):
        t = now + timedelta(seconds=i * cron_interval)
        overdue = last is None or (t - last).total_seconds() >= sync_frequency
        if overdue:
            fired.append((t - now).total_seconds() / HOUR)
            last = t if schedule_from == "start" else t + timedelta(seconds=sync_duration)
    return fired


class TestSchedulingFromTheAttemptStartGivesExactIntervals:
    """Reproduces the table in design notes §1.3."""

    @pytest.mark.parametrize("freq_hours", [6, 12, 24, 72])
    def test_intervals_are_exact_for_every_frequency(self, freq_hours):
        fired = _simulate(
            sync_frequency=freq_hours * HOUR,
            cron_interval=6 * HOUR,
            schedule_from="start",
            sync_duration=18 * 60,  # 18 min, the measured URLhaus worst case at 300 ms
        )
        assert len(fired) >= 3, f"only {len(fired)} syncs simulated; loop is not running"
        gaps = [b - a for a, b in zip(fired, fired[1:])]
        assert all(g == freq_hours for g in gaps), (
            f"expected exact {freq_hours}h intervals, got {gaps}. Scheduling from the "
            "attempt start should make the sync duration irrelevant to cadence."
        )

    def test_the_equal_frequency_case_fires_every_tick(self):
        """`sync_frequency == cron_interval` is the case that failed outright."""
        fired = _simulate(
            sync_frequency=6 * HOUR, cron_interval=6 * HOUR,
            schedule_from="start", sync_duration=18 * 60,
        )
        assert fired[:5] == [0.0, 6.0, 12.0, 18.0, 24.0]

    @pytest.mark.parametrize("freq_hours", [6, 12, 24])
    def test_the_old_behaviour_really_did_drift(self, freq_hours):
        """The control. Without it, the tests above could pass against any scheduler.

        Scheduling from completion must produce intervals STRICTLY LONGER than
        configured — that is the defect, demonstrated rather than described.
        """
        fired = _simulate(
            sync_frequency=freq_hours * HOUR,
            cron_interval=6 * HOUR,
            schedule_from="completion",
            sync_duration=18 * 60,
        )
        gaps = [b - a for a, b in zip(fired, fired[1:])]
        assert gaps, "control simulation produced no intervals"
        assert all(g > freq_hours for g in gaps), (
            f"the control did not reproduce the defect (gaps={gaps}); if scheduling from "
            "completion is now exact too, this whole test file is measuring nothing"
        )


class TestTheSchedulerReadsTheAttemptTimestamp:
    """Source-level, because the behavioural version needs a database and a clock."""

    def _tick_source(self):
        from app.services import feed_scheduler

        return inspect.getsource(feed_scheduler._tick)

    def test_the_due_check_uses_last_attempt_at(self):
        source = self._tick_source()
        assert "feed.last_attempt_at" in source, (
            "_tick no longer reads last_attempt_at. Reading last_sync_at reintroduces "
            "the drift: it is stamped at completion."
        )

    def test_the_due_check_does_not_use_last_sync_at(self):
        """`last_sync_at` is a feed-health field now. Scheduling must not consult it."""
        tree = ast.parse(inspect.getsource(__import__(
            "app.services.feed_scheduler", fromlist=["x"]
        )._tick).lstrip())
        reads = {
            n.attr for n in ast.walk(tree)
            if isinstance(n, ast.Attribute) and n.attr.startswith("last_")
        }
        assert "last_attempt_at" in reads, "extractor found no last_* reads at all"
        assert "last_sync_at" not in reads, (
            "_tick reads last_sync_at. The two columns have different meanings as of "
            "revision a7b8c9d00004 and scheduling must use the attempt timestamp."
        )


class TestTheAttemptTimestampIsStampedBeforeTheFetch:
    """Ordering is the entire fix, so it is asserted on the AST rather than by comment."""

    def test_it_is_captured_before_connector_run(self):
        from app.services import feed_scheduler

        source = inspect.getsource(feed_scheduler._run_feed_sync_inner)
        stamp = source.index("attempt_started_at =")
        run = source.index("await connector.run()")
        assert stamp < run, (
            "attempt_started_at is captured AFTER the fetch, which is the original "
            "defect: the interval becomes sync_frequency + sync_duration."
        )

    def test_it_is_committed_before_the_fetch(self):
        """A crash or spin-down mid-fetch must still count as an attempt.

        Otherwise the feed looks un-attempted and is retried on every subsequent tick —
        which matters here specifically, because §2.8 established that a single URLhaus
        sync can exceed Render's idle window and be killed mid-flight.
        """
        from app.services import feed_scheduler

        source = inspect.getsource(feed_scheduler._run_feed_sync_inner)
        assign = source.index("feed.last_attempt_at = attempt_started_at")
        run = source.index("await connector.run()")
        commit = source.index("await session.commit()", assign)
        assert assign < commit < run, (
            "last_attempt_at is not committed before the fetch begins"
        )


class TestFailureDoesNotLookLikeSuccess:
    """The property the split exists to create."""

    @pytest.mark.parametrize("func_name", ["_run_feed_sync_inner", "_mark_failed"])
    def test_no_failure_path_assigns_last_sync_at(self, func_name):
        """Checks for an ASSIGNMENT, not a mention.

        My first version substring-matched `last_sync_at` and failed against the COMMENT
        explaining why it is not touched — the same shape as the `-r requirements.txt`
        guard that matched inside a comment. An AST walk cannot make that mistake.

        Both functions are covered: `_mark_failed` had the identical defect and was found
        only because this test was parametrized rather than pointed at one function.
        """
        import textwrap

        from app.services import feed_scheduler

        source = textwrap.dedent(inspect.getsource(getattr(feed_scheduler, func_name)))
        tree = ast.parse(source)
        assigned = set()
        for node in ast.walk(tree):
            if isinstance(node, ast.Assign):
                for target in node.targets:
                    if isinstance(target, ast.Attribute):
                        assigned.add(target.attr)
        assert assigned, f"no attribute assignments found in {func_name}; check is vacuous"
        assert "last_sync_at" not in assigned, (
            f"{func_name} assigns last_sync_at on a failure path, so a permanently "
            "failing feed reads as recently synced on dashboard/feed-health — the exact "
            "condition the two-column split was introduced to make visible"
        )

    def test_the_failure_path_increments_consecutive_failures(self):
        from app.services import feed_scheduler

        source = inspect.getsource(feed_scheduler._run_feed_sync_inner)
        assert "feed.consecutive_failures = (feed.consecutive_failures or 0) + 1" in source

    def test_success_resets_the_failure_counter(self):
        from app.services import feed_scheduler

        source = inspect.getsource(feed_scheduler._run_feed_sync_inner)
        assert "feed.consecutive_failures = 0" in source, (
            "a successful sync does not clear the streak, so back-off would never lift"
        )


class TestTheMigrationBackfills:
    """Without the backfill every feed is instantly overdue on the first tick."""

    def test_the_migration_backfills_last_attempt_at_from_last_sync_at(self):
        from pathlib import Path

        path = next(
            Path(__file__).resolve().parents[1].joinpath("alembic/versions").glob(
                "a7b8c9d00004*"
            )
        )
        source = path.read_text(encoding="utf-8")
        assert "UPDATE feed_sources SET last_attempt_at = last_sync_at" in source, (
            "the migration does not backfill. On the first tick after deploy every "
            "feed would have last_attempt_at IS NULL, read as 'never attempted', and "
            "all 8 production feeds would sync simultaneously against a shared host."
        )
