"""feed slug generation helpers turning arbitrary text into URL-safe slugs."""

import re
import unicodedata


NON_ALNUM_RE = re.compile(r"[^a-z0-9]+")


def slugify(text):
    """Return a lowercase, hyphen-separated slug for *text*."""
    normalised = unicodedata.normalize("NFKD", text)
    ascii_only = normalised.encode("ascii", "ignore").decode("ascii")
    slug = NON_ALNUM_RE.sub("-", ascii_only.lower()).strip("-")
    return slug or "n-a"


def unique_slug(slug, existing):
    """Append a counter until *slug* is absent from *existing*."""
    if slug not in existing:
        return slug
    counter = 2
    while "%s-%d" % (slug, counter) in existing:
        counter += 1
    return "%s-%d" % (slug, counter)
