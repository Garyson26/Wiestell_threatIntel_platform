"""Phase 4 Section D4 — exponential back-off on consecutive failures.

``consecutive_failures`` existed from Section A but nothing read it, so it was
bookkeeping. Without back-off a permanently broken feed is retried on every tick
forever: it holds one of the five concurrent sync slots, burns a connection from a pool
sized for a shared host, and writes a ``failed`` row every window. **One dead feed
degrades the others**, which is the cost back-off exists to remove.

Formula (Spec 2 §4.6): ``sync_frequency * 2 ** consecutive_failures``, capped at 3 days.

MEASURED FROM ``last_attempt_at``, and that is not incidental. A failing feed's
``last_sync_at`` is frozen at its last SUCCESS (Section A's split), which may be weeks
ago — so measuring back-off from it would make every retry instantly due and the whole
mechanism would be inert while looking implemented.
"""

import ast
import inspect

import pytest

from app.services.feed_scheduler import (
    _BACKOFF_CAP_SECONDS,
    _effective_interval,
)

HOUR = 3600


class TestTheFormula:
    def test_no_failures_means_no_back_off(self):
        assert _effective_interval(HOUR, 0) == HOUR

    def test_a_negative_or_absent_counter_is_treated_as_zero(self):
        """`consecutive_failures` is NOT NULL DEFAULT 0, but a caller may pass None->0."""
        assert _effective_interval(HOUR, -1) == HOUR

    @pytest.mark.parametrize("failures,expected_hours", [
        (1, 2), (2, 4), (3, 8), (4, 16), (5, 32),
    ])
    def test_it_doubles_per_failure(self, failures, expected_hours):
        assert _effective_interval(HOUR, failures) == expected_hours * HOUR

    def test_it_caps_at_three_days(self):
        assert _BACKOFF_CAP_SECONDS == 3 * 24 * 3600
        assert _effective_interval(HOUR, 20) == _BACKOFF_CAP_SECONDS

    def test_the_cap_is_a_ceiling_not_a_floor(self):
        """A feed whose own cadence exceeds 3 days must not be sped UP by back-off.

        MISP CERT-FR runs at 6h and CISA KEV daily, but a hand-configured weekly feed
        would have sync_frequency > cap. Back-off must never shorten an interval.
        """
        weekly = 7 * 24 * 3600
        assert _effective_interval(weekly, 0) == weekly
        assert _effective_interval(weekly, 3) >= weekly, (
            "back-off returned a SHORTER interval than the feed's own cadence, so a "
            "failing weekly feed would be retried more often than a working one"
        )

    def test_a_huge_counter_does_not_compute_a_huge_integer(self):
        """`2 ** 5000` is exact in Python and pointless to compute before min()."""
        assert _effective_interval(HOUR, 5000) == _BACKOFF_CAP_SECONDS


class TestTheSchedulerUsesIt:
    def _tick_source(self):
        from app.services import feed_scheduler

        return inspect.getsource(feed_scheduler._tick)

    def test_the_due_check_consults_the_effective_interval(self):
        source = self._tick_source()
        assert "_effective_interval(" in source, (
            "the tick compares against the raw sync_frequency, so consecutive_failures "
            "is read by nothing and back-off does not exist"
        )
        assert "feed.consecutive_failures" in source

    def test_it_is_measured_against_last_attempt_at(self):
        """Against last_sync_at the back-off would be inert — see the module docstring."""
        tree = ast.parse(self._tick_source().lstrip())
        reads = {
            n.attr for n in ast.walk(tree)
            if isinstance(n, ast.Attribute) and n.attr.startswith("last_")
        }
        assert "last_attempt_at" in reads
        assert "last_sync_at" not in reads


class TestTheCounterResetsOnEverySuccessfulOutcome:
    """The invariant D3 must not break.

    A 304 Not Modified is a SUCCESSFUL sync — the source is telling us it has nothing
    new. Treating it as a failure would back off a perfectly healthy feed indefinitely,
    and the more reliably unchanged the feed, the worse the back-off. This test exists
    BEFORE the 304 path does, so the path cannot land without resetting.
    """

    def _sync_source(self):
        from app.services import feed_scheduler

        return inspect.getsource(feed_scheduler._run_feed_sync_inner)

    def test_a_successful_ingest_resets_the_counter(self):
        assert "feed.consecutive_failures = 0" in self._sync_source()

    def test_every_non_failure_exit_resets_the_counter(self):
        """Counts reset sites against terminal success paths.

        If D3 adds an early return for 304 that skips the reset, this fails: the number
        of success-shaped exits will exceed the number of resets.
        """
        source = self._sync_source()
        resets = source.count("consecutive_failures = 0")
        # Each of these markers denotes a path that ends the sync WITHOUT it being a
        # failure. Today there is one (a completed ingest). D3 adds a 304 path.
        no_change_markers = source.count("no_change")
        assert resets >= 1, "no reset site at all — back-off would never lift"
        if no_change_markers:
            assert resets >= 2, (
                "a no-change/304 path exists but there is still only one reset site, so "
                "a feed served 304 repeatedly would accumulate consecutive_failures and "
                "back off to the 3-day cap while being perfectly healthy"
            )

    def test_failures_increment_on_both_failure_paths(self):
        from app.services import feed_scheduler

        for name in ("_run_feed_sync_inner", "_mark_failed"):
            source = inspect.getsource(getattr(feed_scheduler, name))
            assert "consecutive_failures = (feed.consecutive_failures or 0) + 1" in source, (
                f"{name} does not increment the failure counter, so back-off never "
                "engages for failures reaching that path"
            )
