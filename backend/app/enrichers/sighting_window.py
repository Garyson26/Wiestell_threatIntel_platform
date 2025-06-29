"""indicator batching helpers for consuming iterables in fixed-size pieces."""

import itertools


def chunked(iterable, width):
    """Yield lists of at most *width* items from *iterable*."""
    iterator = iter(iterable)
    while True:
        batch = list(itertools.islice(iterator, width))
        if not batch:
            return
        yield batch
