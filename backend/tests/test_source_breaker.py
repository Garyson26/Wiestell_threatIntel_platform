import pytest

from backend.app.models.source_breaker import FailFast


def test_passes_results_through():
    breaker = FailFast(max_failures=2)
    assert breaker.run(lambda: 7) == 7


def test_opens_after_repeated_failures():
    breaker = FailFast(max_failures=2)

    def boom():
        raise ValueError("nope")

    for _ in range(2):
        with pytest.raises(ValueError):
            breaker.run(boom)
    assert breaker.is_open is True
