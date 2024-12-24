"""indicator batching helpers for consuming iterables in fixed-size pieces."""

import itertools


def chunked(iterable, batch_size):
    """Yield lists of at most *batch_size* items from *iterable*."""
    iterator = iter(iterable)
    while True:
        batch = list(itertools.islice(iterator, batch_size))
        if not batch:
            return
        yield batch
