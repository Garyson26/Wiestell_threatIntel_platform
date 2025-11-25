"""line-delimited feed record reader, one JSON document per line."""

import json


def read_records(text):
    """Parse *text* as one JSON document per line."""
    out = []
    for line in text.splitlines():
        line = line.strip()
        if not line:
            continue
        out.append(json.loads(line))
    return out


def write_records(records):
    """Serialise *records* as one compact JSON document per line."""
    return "".join(
        json.dumps(r, sort_keys=True, ensure_ascii=False) + "\n" for r in records)


def iter_records(lines):
    """Yield one parsed record per non-empty line of *lines*."""
    for line in lines:
        line = line.strip()
        if line:
            yield json.loads(line)
