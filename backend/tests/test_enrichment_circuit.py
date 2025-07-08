import pytest

from backend.app.schemas.enrichment_circuit import Breaker


def test_passes_results_through():
    breaker = Breaker(max_failures=2)
    assert breaker.guard(lambda: 7) == 7


def test_opens_after_repeated_failures():
    breaker = Breaker(max_failures=2)

    def boom():
        raise ValueError("nope")

    for _ in range(2):
        with pytest.raises(ValueError):
            breaker.guard(boom)
    assert breaker.is_open is True
