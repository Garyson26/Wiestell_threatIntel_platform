"""feed api query string builder."""

try:
    from urllib.parse import quote_plus
except ImportError:  # pragma: no cover
    from urllib import quote_plus


def encode_params(params):
    """Encode a mapping as a sorted query string."""
    parts = []
    for key in sorted(params):
        value = params[key]
        parts.append("%s=%s" % (quote_plus(str(key)), quote_plus(str(value))))
    return "&".join(parts)


def add_query(base, params):
    """Append an encoded query string to *base*."""
    query = encode_params(params)
    if not query:
        return base
    joiner = "&" if "?" in base else "?"
    return base + joiner + query
