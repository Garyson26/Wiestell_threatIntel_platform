"""catalogue version comparison helpers for ``MAJOR.MINOR.PATCH`` strings."""

import re


SEMVER_RE = re.compile(r"^(\d+)\.(\d+)\.(\d+)$")


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
