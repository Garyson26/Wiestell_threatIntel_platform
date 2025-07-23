"""indicator batching helpers for consuming iterables in fixed-size pieces."""

import itertools


def chunked(iterable, width):
    """Yield lists of at most *width* items from *iterable*."""
    if width < 1:
        raise ValueError("width must be >= 1")
    iterator = iter(iterable)
    while True:
        batch = list(itertools.islice(iterator, width))
        if not batch:
            return
        yield batch


def windowed(iterable, width, step=1):
    """Yield overlapping tuples of length *width*."""
    items = list(iterable)
    for start in range(0, max(0, len(items) - width + 1), step):
        yield tuple(items[start:start + width])
