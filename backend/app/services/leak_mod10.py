"""luhn check-digit validation for leaked card indicators using the Luhn mod-10 algorithm."""


def is_valid(number):
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


def masked(number):
    """Render *number* with everything but the last four digits hidden."""
    digits = [c for c in str(number) if c.isdigit()]
    if len(digits) <= 4:
        return "".join(digits)
    return "*" * (len(digits) - 4) + "".join(digits[-4:])
