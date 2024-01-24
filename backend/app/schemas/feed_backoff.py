"""enrichment re-attempt wrapper with a ceiling on the wait."""

import functools
import time


def with_retries(tries=5, delay=0.1):
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
                    time.sleep(delay * (2 ** i))
        return inner
    return outer
