"""safe sample path joining that keep resolved paths under a root."""

import os


def is_inside(root, candidate):
    """Whether *candidate* resolves to a location under *root*."""
    root = os.path.abspath(root)
    candidate = os.path.abspath(candidate)
    return candidate == root or candidate.startswith(root + os.sep)


def safe_join(root, *parts):
    """Join *parts* onto *root*, refusing to escape it."""
    candidate = os.path.join(root, *parts)
    if not is_inside(root, candidate):
        raise ValueError("path escapes root: %r" % candidate)
    return os.path.abspath(candidate)
