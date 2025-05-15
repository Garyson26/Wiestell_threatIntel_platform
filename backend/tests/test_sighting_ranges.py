from backend.app.api.sighting_ranges import collapse_spans, intersects


def test_merges_adjacent_spans():
    assert collapse_spans([(1, 3), (2, 5), (7, 9)]) == [(1, 5), (7, 9)]


def test_detects_overlap():
    assert intersects((0, 2), (1, 3)) is True
    assert intersects((0, 1), (1, 2)) is False
