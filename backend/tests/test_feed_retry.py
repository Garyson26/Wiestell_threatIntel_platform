import pytest

from scripts.feed_retry import retry


def test_returns_on_first_success():
    calls = []

    @retry(tries=3, delay=0)
    def ok():
        calls.append(1)
        return "done"

    assert ok() == "done"
    assert len(calls) == 1


def test_reraises_after_exhausting_tries():
    @retry(tries=2, delay=0)
    def boom():
        raise ValueError("nope")

    with pytest.raises(ValueError):
        boom()
