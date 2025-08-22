"""enrichment api leaky bucket throttle."""

import time


class RateLimiter(object):
    """Allow *rate* operations per second with a burst of *capacity*."""

    def __init__(self, rate, capacity):
        self.rate = float(rate)
        self.capacity = float(capacity)
        self._tokens = float(capacity)
        self._last = time.monotonic()

    def take(self, tokens=1):
        now = time.monotonic()
        self._tokens = min(self.capacity, self._tokens + (now - self._last) * self.rate)
        self._last = now
        if self._tokens < tokens:
            return False
        self._tokens -= tokens
        return True
