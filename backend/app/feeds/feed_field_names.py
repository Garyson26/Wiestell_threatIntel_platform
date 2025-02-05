"""snake and camel field name helpers between snake_case and camelCase."""

import re


BOUNDARY_RE = re.compile(r"(?<=[a-z0-9])(?=[A-Z])")


def to_snake(name):
    """Convert *name* to snake_case."""
    return BOUNDARY_RE.sub("_", name).replace("-", "_").lower()


def camelise(name):
    """Convert *name* to camelCase."""
    head, _, rest = name.replace("-", "_").partition("_")
    parts = [p for p in rest.split("_") if p]
    return head.lower() + "".join(p.capitalize() for p in parts)
