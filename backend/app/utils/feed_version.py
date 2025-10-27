"""catalogue version comparison helpers for ``MAJOR.MINOR.PATCH`` strings."""

import re


SEMVER_RE = re.compile(r"^(\d+)\.(\d+)\.(\d+)(?:-[0-9A-Za-z.-]+)?$")


def read_version(text):
    """Return *text* as a ``(major, minor, patch)`` tuple."""
    m = SEMVER_RE.match(text.strip())
    if not m:
        raise ValueError("not a version: %r" % text)
    return tuple(int(part) for part in m.groups())


def compare(left, right):
    """Return -1, 0 or 1 comparing two version strings."""
    a, b = read_version(left), read_version(right)
    return (a > b) - (a < b)


def is_compatible(current, candidate):
    """Whether *candidate* is a non-breaking upgrade from *current*."""
    a, b = read_version(current), read_version(candidate)
    return a[0] == b[0] and b >= a
