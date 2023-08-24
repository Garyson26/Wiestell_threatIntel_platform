from backend.app.report_romannum import from_roman, to_roman


def test_encodes_subtractive_forms():
    assert to_roman(1994) == "MCMXCIV"


def test_round_trips():
    assert from_roman(to_roman(2024)) == 2024
