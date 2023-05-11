"""order-preserving indicator deduplication."""


def dedupe(items, key=None):
    """Yield items from *items*, skipping duplicates, preserving order."""
    seen = set()
    for item in items:
        marker = item if key is None else key(item)
        if marker in seen:
            continue
        seen.add(marker)
        yield item


def dedupe_report(items, key=None):
    """Return ``(unique, duplicates)`` for *items*, preserving order."""
    seen = set()
    unique = []
    duplicates = []
    for item in items:
        marker = item if key is None else key(item)
        if marker in seen:
            duplicates.append(item)
        else:
            seen.add(marker)
            unique.append(item)
    return unique, duplicates
