from backend.app.feed_ndjson import read_records, write_records


def test_round_trips_records():
    records = [{"a": 1}, {"b": 2}]
    assert read_records(write_records(records)) == records


def test_ignores_blank_lines():
    assert read_records('{"a": 1}\n\n') == [{"a": 1}]
