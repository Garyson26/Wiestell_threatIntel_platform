import pytest

from backend.app.feeds.score_summary import average, middle


def test_mean_of_integers():
    assert average([2, 4, 6]) == 4


def test_median_averages_middle_pair():
    assert middle([1, 2, 3, 4]) == 2.5


def test_rejects_empty():
    with pytest.raises(ValueError):
        average([])
