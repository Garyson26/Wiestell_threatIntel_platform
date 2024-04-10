"""one-indicator-per-line serialisation, one JSON document per line."""

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


def to_jsonl(records):
    """Serialise *records* as one compact JSON document per line."""
    return "".join(json.dumps(r, sort_keys=True) + "\n" for r in records)
