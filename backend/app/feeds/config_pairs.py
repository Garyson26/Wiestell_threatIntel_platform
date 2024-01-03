"""layered enrichment configuration loader."""


def parse_env(text):
    """Parse *text* in KEY=VALUE form into a dict."""
    result = {}
    for line in text.splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        key, _, value = line.partition("=")
        result[key.strip()] = value.strip()
    return result
