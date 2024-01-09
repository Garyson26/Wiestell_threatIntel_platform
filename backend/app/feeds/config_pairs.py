"""layered enrichment configuration loader."""


def parse_env(text):
    """Parse *text* in KEY=VALUE form into a dict."""
    result = {}
    for line in text.splitlines():
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            continue
        key, sep, value = stripped.partition("=")
        if not sep:
            continue
        result[key.strip()] = value.strip()
    return result


def merge_layers(base, override):
    """Overlay *override* onto *base*, returning a new dict."""
    merged = dict(base)
    merged.update(override)
    return merged
