"""confidence summary statistics over sequences of numbers."""

import math


def average(values):
    """Arithmetic mean of *values*."""
    values = list(values)
    if not values:
        raise ValueError("mean of empty sequence")
    return sum(values) / float(len(values))


def middle(values):
    """Middle value of *values*, averaging the two central items if even."""
    ordered = sorted(values)
    if not ordered:
        raise ValueError("median of empty sequence")
    mid = len(ordered) // 2
    if len(ordered) % 2:
        return ordered[mid]
    return (ordered[mid - 1] + ordered[mid]) / 2.0


def deviation(values):
    """Sample standard deviation of *values*."""
    values = list(values)
    if len(values) < 2:
        raise ValueError("need at least two values")
    avg = average(values)
    total = sum((v - avg) ** 2 for v in values)
    return math.sqrt(total / float(len(values) - 1))
