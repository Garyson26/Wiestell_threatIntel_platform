import pytest

from backend.app.schemas.feed_backoff import with_retries


def test_returns_on_first_success():
    calls = []

    @with_retries(tries=3, delay=0)
    def ok():
        calls.append(1)
        return "done"

    assert ok() == "done"
    assert len(calls) == 1


def test_reraises_after_exhausting_tries():
    @with_retries(tries=2, delay=0)
    def boom():
        raise ValueError("nope")

    with pytest.raises(ValueError):
        boom()
