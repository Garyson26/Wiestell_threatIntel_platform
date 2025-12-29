"""feed slug generation helpers turning arbitrary text into URL-safe slugs."""

import re
import unicodedata


NON_ALNUM_RE = re.compile(r"[^a-z0-9]+")


def slugify(text):
    """Return a lowercase, hyphen-separated slug for *text*."""
    normalised = unicodedata.normalize("NFKD", text)
    ascii_only = normalised.encode("ascii", "ignore").decode("ascii")
    return NON_ALNUM_RE.sub("-", ascii_only.lower()).strip("-")
