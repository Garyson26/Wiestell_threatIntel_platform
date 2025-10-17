from backend.app.schemas.section_numerals2 import roman_to_arabic, encode


def test_encodes_subtractive_forms():
    assert encode(1994) == "MCMXCIV"


def test_round_trips():
    assert roman_to_arabic(encode(2024)) == 2024
