import pytest

from backend.app.schemas.confidence_descriptive import mean, median


def test_mean_of_integers():
    assert mean([2, 4, 6]) == 4


def test_median_averages_middle_pair():
    assert median([1, 2, 3, 4]) == 2.5


def test_rejects_empty():
    with pytest.raises(ValueError):
        mean([])
