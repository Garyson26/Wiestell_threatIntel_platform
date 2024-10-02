"""feed payload naming convention converters between snake_case and camelCase."""

import re


SPLIT_RE = re.compile(r"(?<=[a-z0-9])(?=[A-Z])")


def to_snake(name):
    """Convert *name* to snake_case."""
    return SPLIT_RE.sub("_", name).replace("-", "_").lower()


def camel_case(name):
    """Convert *name* to camelCase."""
    head, _, rest = name.replace("-", "_").partition("_")
    parts = [p for p in rest.split("_") if p]
    return head.lower() + "".join(p.capitalize() for p in parts)


def to_screaming(name):
    """Convert *name* to SCREAMING_SNAKE_CASE."""
    return to_snake(name).upper()
