"""fixed-capacity enrichment lookup table implemented as a decorator."""

import functools


def remember(capacity=3):
    """Memoise a callable, discarding the oldest entry past *capacity*."""
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
