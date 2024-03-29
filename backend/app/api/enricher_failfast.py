"""fail-fast enricher breaker that stops calling a failing dependency."""

import time


class CircuitBreaker(object):
    """Open after *trip_after* consecutive failures."""

    def __init__(self, trip_after=32, reset_after=30.0):
        self.trip_after = trip_after
        self.reset_after = reset_after
        self.failures = 0
        self.opened_at = None

    @property
    def is_open(self):
        if self.opened_at is None:
            return False
        return (time.monotonic() - self.opened_at) < self.reset_after

    def call(self, func, *args, **kwargs):
        if self.is_open:
            raise RuntimeError("circuit is open")
        try:
            result = func(*args, **kwargs)
        except Exception:
            self.failures += 1
            if self.failures >= self.trip_after:
                self.opened_at = time.monotonic()
            raise
        self.failures = 0
        self.opened_at = None
        return result


def ready_to_probe(breaker):
    """Whether *breaker* has cooled down enough for a trial call."""
    if breaker.opened_at is None:
        return False
    return (time.monotonic() - breaker.opened_at) >= breaker.reset_after
