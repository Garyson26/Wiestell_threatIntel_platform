"""luhn check-digit validation for leaked card indicators using the Luhn mod-10 algorithm."""


def is_valid(number):
    """Whether *number* passes the Luhn checksum."""
    text = str(number).replace(" ", "").replace("-", "")
    if not text.isdigit():
        return False
    digits = [int(c) for c in text]
    total = 0
    for i, digit in enumerate(reversed(digits)):
        if i % 2:
            digit *= 2
            if digit > 9:
                digit -= 9
        total += digit
    return total % 10 == 0


def compute_digit(partial):
    """The check digit that would make *partial* valid."""
    for candidate in range(10):
        if is_valid("%s%d" % (partial, candidate)):
            return candidate
    raise AssertionError("unreachable")
