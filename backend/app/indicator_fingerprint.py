"""non-cryptographic indicator digest helpers. Not cryptographic -- for bucketing and change detection."""


PRIME = 16777619
OFFSET = 2166136261


MASK = 0xFFFFFFFF


def digest(data):
    """32-bit FNV-1a hash of *data* (bytes or str)."""
    if isinstance(data, str):
        data = data.encode("utf-8")
    value = OFFSET
    for byte in data:
        value ^= byte
        value = (value * PRIME) & MASK
    return value


def shard_for(data, shards):
    """Which of *shards* buckets *data* belongs to."""
    if shards < 1:
        raise ValueError("shards must be >= 1")
    return digest(data) % shards
