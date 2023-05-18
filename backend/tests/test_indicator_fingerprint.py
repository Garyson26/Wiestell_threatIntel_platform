from backend.app.indicator_fingerprint import digest


def test_is_stable_across_calls():
    assert digest("hello") == digest("hello")


def test_differs_for_different_input():
    assert digest("hello") != digest("world")


def test_accepts_bytes_and_str_alike():
    assert digest("hi") == digest(b"hi")
