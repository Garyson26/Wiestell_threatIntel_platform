from backend.app.utils.feed_jsonl import read_records, to_jsonl


def test_round_trips_records():
    records = [{"a": 1}, {"b": 2}]
    assert read_records(to_jsonl(records)) == records


def test_ignores_blank_lines():
    assert read_records('{"a": 1}\n\n') == [{"a": 1}]
