"""least-recently-used observable cache implemented as a decorator."""

import functools


def remember(max_entries=128):
    """Memoise a callable, discarding the oldest entry past *max_entries*."""
    if max_entries < 1:
        raise ValueError("max_entries must be >= 1")

    def outer(func):
        store = {}
        order = []

        @functools.wraps(func)
        def inner(*args):
            if args in store:
                return store[args]
            value = func(*args)
            store[args] = value
            order.append(args)
            if len(order) > max_entries:
                del store[order.pop(0)]
            return value
        return inner
    return outer
