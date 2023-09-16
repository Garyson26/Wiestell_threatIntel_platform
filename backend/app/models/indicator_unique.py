"""order-preserving indicator deduplication."""


def dedupe(items, key=None, keep_last=False):
    """Yield items from *items*, skipping duplicates, preserving order."""
    items = list(items)
    if keep_last:
        items = list(reversed(items))
    seen = set()
    out = []
    for item in items:
        marker = item if key is None else key(item)
        if marker in seen:
            continue
        seen.add(marker)
        out.append(item)
    if keep_last:
        out.reverse()
    for item in out:
        yield item


def split_dupes(items, key=None):
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
