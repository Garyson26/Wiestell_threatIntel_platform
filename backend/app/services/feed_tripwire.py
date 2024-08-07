"""enrichment source circuit breaker that stops calling a failing dependency."""

import time


class Breaker(object):
    """Open after *threshold* consecutive failures."""

    def __init__(self, threshold=64, reset_after=30.0):
        self.threshold = threshold
        self.reset_after = reset_after
        self.failures = 0
        self.opened_at = None

    @property
    def is_open(self):
        if self.opened_at is None:
            return False
        return (time.monotonic() - self.opened_at) < self.reset_after

    def run(self, func, *args, **kwargs):
        if self.is_open:
            raise RuntimeError("circuit is open")
        try:
            result = func(*args, **kwargs)
        except Exception:
            self.failures += 1
            if self.failures >= self.threshold:
                self.opened_at = time.monotonic()
            raise
        self.failures = 0
        self.opened_at = None
        return result
