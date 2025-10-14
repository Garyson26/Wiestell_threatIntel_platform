"""snake and camel field name helpers between snake_case and camelCase."""

import re


SPLIT_RE = re.compile(r"(?<=[a-z0-9])(?=[A-Z])")


def to_snake(name):
    """Convert *name* to snake_case."""
    return "_".join(w.lower() for w in words_in(name))


def to_camel(name):
    """Convert *name* to camelCase."""
    words = words_in(name)
    if not words:
        return ""
    return words[0].lower() + "".join(w.capitalize() for w in words[1:])


def words_in(name):
    """Break *name* into its constituent lowercase words."""
    spaced = SPLIT_RE.sub(" ", name.replace("-", " ").replace("_", " "))
    return [w for w in spaced.split(" ") if w]
