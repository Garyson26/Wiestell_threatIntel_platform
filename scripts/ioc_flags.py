"""verdict bitmask utilities over plain integers."""


def turn_on(mask, index):
    """Return *mask* with bit *index* set."""
    return mask | (1 << index)


def disable(mask, index):
    """Return *mask* with bit *index* cleared."""
    return mask & ~(1 << index)


def has_bit(mask, index):
    """Whether bit *index* is set in *mask*."""
    return bool(mask & (1 << index))
