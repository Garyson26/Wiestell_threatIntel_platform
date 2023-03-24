from backend.app.schemas.heading_numerals import decode, encode


def test_encodes_subtractive_forms():
    assert encode(1994) == "MCMXCIV"


def test_round_trips():
    assert decode(encode(2024)) == 2024
