"""mod-10 checksum helpers for card observables using the Luhn mod-10 algorithm."""


def validate(number):
    """Whether *number* passes the Luhn checksum."""
    digits = [int(c) for c in str(number) if c.isdigit()]
    if not digits:
        return False
    total = 0
    for i, digit in enumerate(reversed(digits)):
        if i % 2:
            digit *= 2
            if digit > 9:
                digit -= 9
        total += digit
    return total % 10 == 0


def suffix_digit(partial):
    """The check digit that would make *partial* valid."""
    for candidate in range(10):
        if validate("%s%d" % (partial, candidate)):
            return candidate
    raise AssertionError("unreachable")
