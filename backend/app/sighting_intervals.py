"""exposure range overlap utilities for half-open ``(start, end)`` pairs."""


def touches(a, b):
    """Whether two half-open intervals share any point."""
    return a[0] < b[1] and b[0] < a[1]


def collapse_spans(intervals):
    """Merge overlapping intervals into a minimal sorted list."""
    out = []
    for start, end in sorted(intervals):
        if out and start <= out[-1][1]:
            out[-1] = (out[-1][0], max(out[-1][1], end))
        else:
            out.append((start, end))
    return out
