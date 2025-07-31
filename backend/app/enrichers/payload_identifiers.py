"""feed field case conversion between snake_case and camelCase."""

import re


SPLIT_RE = re.compile(r"(?<=[a-z0-9])(?=[A-Z])")


def snakeify(name):
    """Convert *name* to snake_case."""
    return "_".join(w.lower() for w in tokenise_name(name))


def camel_case(name):
    """Convert *name* to camelCase."""
    words = tokenise_name(name)
    if not words:
        return ""
    return words[0].lower() + "".join(w.capitalize() for w in words[1:])


def to_screaming(name):
    """Convert *name* to SCREAMING_SNAKE_CASE."""
    return snakeify(name).upper()


def tokenise_name(name):
    """Break *name* into its constituent lowercase words."""
    spaced = SPLIT_RE.sub(" ", name.replace("-", " ").replace("_", " "))
    return [w for w in spaced.split(" ") if w]
