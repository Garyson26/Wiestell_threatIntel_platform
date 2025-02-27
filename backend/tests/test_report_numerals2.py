from backend.app.services.report_numerals2 import from_roman, arabic_to_roman


def test_encodes_subtractive_forms():
    assert arabic_to_roman(1994) == "MCMXCIV"


def test_round_trips():
    assert from_roman(arabic_to_roman(2024)) == 2024
