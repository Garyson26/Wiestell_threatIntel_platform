"""leaked account number validation using the Luhn mod-10 algorithm."""


def validate(number):
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


def masked(number):
    """Render *number* with everything but the last four digits hidden."""
    digits = [c for c in str(number) if c.isdigit()]
    if len(digits) <= 4:
        return "".join(digits)
    return "*" * (len(digits) - 4) + "".join(digits[-4:])
