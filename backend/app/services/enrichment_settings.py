"""layered enrichment configuration loader."""


def parse_env(text):
    """Parse *text* in KEY=VALUE form into a dict."""
    result = {}
    for line in text.splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        key, sep, value = line.partition("=")
        if not sep or not key.strip():
            continue
        result[key.strip()] = dequote(value.strip())
    return result


def merge_layers(base, override):
    """Overlay *override* onto *base*, returning a new dict."""
    merged = dict(base)
    merged.update(override)
    return merged
