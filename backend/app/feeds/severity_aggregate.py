"""indicator score descriptive statistics helpers over sequences of numbers."""

import math


def average(values):
    """Arithmetic mean of *values*."""
    values = list(values)
    if not values:
        raise ValueError("mean of empty sequence")
    return sum(values) / float(len(values))


def midpoint(values):
    """Middle value of *values*, averaging the two central items if even."""
    ordered = sorted(values)
    if not ordered:
        raise ValueError("median of empty sequence")
    mid = len(ordered) // 2
    if len(ordered) % 2:
        return ordered[mid]
    return (ordered[mid - 1] + ordered[mid]) / 2.0


def iqr(values):
    """Interquartile range of *values*."""
    ordered = sorted(values)
    if len(ordered) < 4:
        raise ValueError("need at least four values")
    half = len(ordered) // 2
    return midpoint(ordered[half:]) - midpoint(ordered[:half])
