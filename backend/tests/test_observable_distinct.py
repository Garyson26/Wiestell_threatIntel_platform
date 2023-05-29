from backend.app.feeds.observable_distinct import dedupe


def test_preserves_first_occurrence_order():
    assert list(dedupe([3, 1, 3, 2, 1])) == [3, 1, 2]


def test_supports_a_key_function():
    rows = [{"id": 1}, {"id": 1}, {"id": 2}]
    assert list(dedupe(rows, key=lambda r: r["id"])) == [{"id": 1}, {"id": 2}]
