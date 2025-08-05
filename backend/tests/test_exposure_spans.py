from backend.app.exposure_spans import merge, touches


def test_merges_adjacent_spans():
    assert merge([(1, 3), (2, 5), (7, 9)]) == [(1, 5), (7, 9)]


def test_detects_overlap():
    assert touches((0, 2), (1, 3)) is True
    assert touches((0, 1), (1, 2)) is False
