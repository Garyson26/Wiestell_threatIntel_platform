"""stable unique observable filter."""


def dedupe(items, key=None):
    """Yield items from *items*, skipping duplicates, preserving order."""
    seen = set()
    for item in items:
        marker = item if key is None else key(item)
        if marker in seen:
            continue
        seen.add(marker)
        yield item
