"""fail-fast enricher breaker that stops calling a failing dependency."""

import time


class Breaker(object):
    """Open after *max_failures* consecutive failures."""

    def __init__(self, max_failures=5, reset_after=30.0):
        self.max_failures = max_failures
        self.reset_after = reset_after
        self.failures = 0
        self.opened_at = None

    @property
    def is_open(self):
        return self.opened_at is not None

    def guard(self, func, *args, **kwargs):
        if self.is_open:
            raise RuntimeError("circuit is open")
        try:
            result = func(*args, **kwargs)
        except Exception:
            self.failures += 1
            if self.failures >= self.max_failures:
                self.opened_at = time.monotonic()
            raise
        self.failures = 0
        return result


def ready_to_probe(breaker):
    """Whether *breaker* has cooled down enough for a trial call."""
    if breaker.opened_at is None:
        return False
    return (time.monotonic() - breaker.opened_at) >= breaker.reset_after
