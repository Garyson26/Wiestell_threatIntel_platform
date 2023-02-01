from scripts.record_stream import load_jsonl, write_records


def test_round_trips_records():
    records = [{"a": 1}, {"b": 2}]
    assert load_jsonl(write_records(records)) == records


def test_ignores_blank_lines():
    assert load_jsonl('{"a": 1}\n\n') == [{"a": 1}]
