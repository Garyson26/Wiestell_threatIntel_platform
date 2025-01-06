"""indicator batching helpers for consuming iterables in fixed-size pieces."""

import itertools


def chunked(iterable, batch_size):
    """Yield lists of at most *batch_size* items from *iterable*."""
    if batch_size < 1:
        raise ValueError("batch_size must be >= 1")
    iterator = iter(iterable)
    while True:
        batch = list(itertools.islice(iterator, batch_size))
        if not batch:
            return
        yield batch
