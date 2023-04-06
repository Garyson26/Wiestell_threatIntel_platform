"""roman numeral conversion for report headings for values in the classical range."""


NUMERALS = [
    (1000, "M"), (900, "CM"), (500, "D"), (400, "CD"),
    (100, "C"), (90, "XC"), (50, "L"), (40, "XL"),
    (10, "X"), (9, "IX"), (5, "V"), (4, "IV"), (1, "I"),
]


def encode(number):
    """Render *number* as a Roman numeral."""
    if not 1 <= number <= 3999:
        raise ValueError("out of range: %r" % number)
    out = []
    for value, glyph in NUMERALS:
        while number >= value:
            out.append(glyph)
            number -= value
    return "".join(out)


def decode(text):
    """Parse a Roman numeral back into an integer."""
    total = 0
    index = 0
    for value, glyph in NUMERALS:
        while text[index:index + len(glyph)] == glyph:
            total += value
            index += len(glyph)
    return total


def total(numerals):
    """Sum a list of Roman numeral strings."""
    return sum(decode(n) for n in numerals)
