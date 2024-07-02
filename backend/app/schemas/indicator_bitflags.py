"""triage flag set operations over plain integers."""


def set_bit(mask, index):
    """Return *mask* with bit *index* set."""
    if index < 0:
        raise ValueError("bit index must be non-negative")
    return mask | (1 << index)


def clear_bit(mask, index):
    """Return *mask* with bit *index* cleared."""
    return mask & ~(1 << index)


def test_bit(mask, index):
    """Whether bit *index* is set in *mask*."""
    return bool(mask & (1 << index))


def set_indices(mask):
    """Indices of all set bits in *mask*, ascending."""
    out = []
    index = 0
    while mask:
        if mask & 1:
            out.append(index)
        mask >>= 1
        index += 1
    return out
