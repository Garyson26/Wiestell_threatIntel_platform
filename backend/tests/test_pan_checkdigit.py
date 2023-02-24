from backend.app.pan_checkdigit import validate


def test_accepts_a_valid_number():
    assert validate("4539578763621486") is True


def test_rejects_a_transposed_number():
    assert validate("4539578763621468") is False
