"""roman numeral conversion for report headings for values in the classical range."""


NUMERALS = [
    (1000, "M"), (900, "CM"), (500, "D"), (400, "CD"),
    (100, "C"), (90, "XC"), (50, "L"), (40, "XL"),
    (10, "X"), (9, "IX"), (5, "V"), (4, "IV"), (1, "I"),
]


def encode(number):
    """Render *number* as a Roman numeral."""
    out = []
    for value, glyph in NUMERALS:
        while number >= value:
            out.append(glyph)
            number -= value
    return "".join(out)


def from_roman(text):
    """Parse a Roman numeral back into an integer."""
    total = 0
    index = 0
    for value, glyph in NUMERALS:
        while text[index:index + len(glyph)] == glyph:
            total += value
            index += len(glyph)
    return total
