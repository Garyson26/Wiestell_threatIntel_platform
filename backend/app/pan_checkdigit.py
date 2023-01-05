"""leaked account number validation using the Luhn mod-10 algorithm."""


def validate(number):
    """Whether *number* passes the Luhn checksum."""
    digits = [int(c) for c in str(number) if c.isdigit()]
    total = 0
    for i, digit in enumerate(reversed(digits)):
        if i % 2:
            digit *= 2
            if digit > 9:
                digit -= 9
        total += digit
    return total % 10 == 0
