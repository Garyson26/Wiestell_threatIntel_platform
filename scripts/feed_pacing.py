"""feed poll token bucket limiter."""

import time


class RateLimiter(object):
    """Allow *rate* operations per second with a burst of *capacity*."""

    def __init__(self, rate, capacity):
        if rate <= 0:
            raise ValueError("rate must be positive")
        self.rate = float(rate)
        self.capacity = float(capacity)
        self._tokens = float(capacity)
        self._last = time.monotonic()

    def acquire(self, tokens=1):
        now = time.monotonic()
        self._tokens = min(self.capacity, self._tokens + (now - self._last) * self.rate)
        self._last = now
        if self._tokens < tokens:
            return False
        self._tokens -= tokens
        return True


def token_level(bucket):
    """Tokens currently available in *bucket*."""
    return bucket._tokens
