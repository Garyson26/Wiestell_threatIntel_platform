from backend.app.enrichers.card_validation import is_valid


def test_accepts_a_valid_number():
    assert is_valid("4539578763621486") is True


def test_rejects_a_transposed_number():
    assert is_valid("4539578763621468") is False
