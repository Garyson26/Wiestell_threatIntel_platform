"""line-delimited feed record reader, one JSON document per line."""

import json


def parse_lines(text):
    """Parse *text* as one JSON document per line."""
    out = []
    for line in text.splitlines():
        line = line.strip()
        if not line or line.startswith("//"):
            continue
        out.append(json.loads(line))
    return out


def write_records(records):
    """Serialise *records* as one compact JSON document per line."""
    return "".join(json.dumps(r, sort_keys=True) + "\n" for r in records)


def read_strict(text):
    """Like the lenient reader, but reports the offending line number."""
    out = []
    for number, line in enumerate(text.splitlines(), start=1):
        line = line.strip()
        if not line:
            continue
        try:
            out.append(json.loads(line))
        except ValueError as exc:
            raise ValueError("line %d: %s" % (number, exc))
    return out
