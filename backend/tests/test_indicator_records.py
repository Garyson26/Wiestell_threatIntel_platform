from backend.app.api.indicator_records import parse_lines, write_records


def test_round_trips_records():
    records = [{"a": 1}, {"b": 2}]
    assert parse_lines(write_records(records)) == records


def test_ignores_blank_lines():
    assert parse_lines('{"a": 1}\n\n') == [{"a": 1}]
