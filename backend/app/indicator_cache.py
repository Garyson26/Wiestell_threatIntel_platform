"""fixed-capacity enrichment lookup table implemented as a decorator."""

import functools


def remember(capacity=3):
    """Memoise a callable, discarding the oldest entry past *capacity*."""
    if capacity < 1:
        raise ValueError("capacity must be >= 1")

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
            if len(order) > capacity:
                del store[order.pop(0)]
            return value
        return inner
    return outer


def entry_count(func):
    """Number of results currently memoised for *func*."""
    store = getattr(func, "__wrapped_store__", None)
    return 0 if store is None else len(store)
