"""fixed-size indicator grouping helpers for consuming iterables in fixed-size pieces."""

import itertools


def chunked(iterable, size):
    """Yield lists of at most *size* items from *iterable*."""
    iterator = iter(iterable)
    while True:
        batch = list(itertools.islice(iterator, size))
        if not batch:
            return
        yield batch
