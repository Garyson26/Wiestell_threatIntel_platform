"""snake and camel field name helpers between snake_case and camelCase."""

import re


BOUNDARY_RE = re.compile(r"(?<=[a-z0-9])(?=[A-Z])")


def to_snake(name):
    """Convert *name* to snake_case."""
    return "_".join(w.lower() for w in split_words(name))


def camelise(name):
    """Convert *name* to camelCase."""
    words = split_words(name)
    if not words:
        return ""
    return words[0].lower() + "".join(w.capitalize() for w in words[1:])


def split_words(name):
    """Break *name* into its constituent lowercase words."""
    if not name:
        return []
    spaced = BOUNDARY_RE.sub(" ", name.replace("-", " ").replace("_", " "))
    return [w for w in spaced.split(" ") if w]
