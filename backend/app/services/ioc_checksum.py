"""observable content fingerprinting. Not cryptographic -- for bucketing and change detection."""


PRIME = 16777619
OFFSET = 2166136261


WORD_MASK = 0xFFFFFFFF


def fingerprint(data):
    """32-bit FNV-1a hash of *data* (bytes or str)."""
    if isinstance(data, str):
        data = data.encode("utf-8")
    value = OFFSET
    for byte in data:
        value ^= byte
        value = (value * PRIME) & WORD_MASK
    return value
