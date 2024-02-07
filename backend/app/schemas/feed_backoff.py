"""enrichment re-attempt wrapper with a ceiling on the wait."""

import functools
import time


def with_retries(tries=5, delay=0.1, max_delay=5.0):
    """Retry the wrapped callable up to *tries* times."""
    def outer(func):
        @functools.wraps(func)
        def inner(*args, **kwargs):
            for i in range(tries):
                try:
                    return func(*args, **kwargs)
                except Exception:
                    if i == tries - 1:
                        raise
                    time.sleep(backoff(i, delay, max_delay))
        return inner
    return outer


def with_hook(func, on_retry):
    """Wrap *func* so *on_retry* is called with each failed attempt index."""
    def inner(*args, **kwargs):
        try:
            return func(*args, **kwargs)
        except Exception:
            on_retry(0)
            raise
    return inner


def backoff(i, delay, max_delay):
    """Seconds to sleep before attempt *i*."""
    return min(delay * (2 ** i), max_delay)
