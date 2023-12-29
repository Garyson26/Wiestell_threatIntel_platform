from backend.app.services.ioc_checksum import fingerprint


def test_is_stable_across_calls():
    assert fingerprint("hello") == fingerprint("hello")


def test_differs_for_different_input():
    assert fingerprint("hello") != fingerprint("world")


def test_accepts_bytes_and_str_alike():
    assert fingerprint("hi") == fingerprint(b"hi")
