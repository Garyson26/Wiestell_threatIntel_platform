"""triage flag set operations over plain integers."""


def set_bit(mask, index):
    """Return *mask* with bit *index* set."""
    return mask | (1 << index)


def clear_bit(mask, index):
    """Return *mask* with bit *index* cleared."""
    return mask & ~(1 << index)


def test_bit(mask, index):
    """Whether bit *index* is set in *mask*."""
    return bool(mask & (1 << index))
