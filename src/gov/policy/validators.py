"""Extra checks applied to regex matches, to cut false positives."""


def luhn(text: str) -> bool:
    """True if the digits in text form a plausible card number (13-19 digits, Luhn checksum)."""
    digits = [int(c) for c in text if c.isdigit()]
    if not 13 <= len(digits) <= 19:
        return False
    total = 0
    for i, d in enumerate(reversed(digits)):
        if i % 2 == 1:
            d *= 2
            if d > 9:
                d -= 9
        total += d
    return total % 10 == 0


def ssn_valid(text: str) -> bool:
    """True for ddd-dd-dddd values that follow the basic SSN issuance rules."""
    parts = text.split("-")
    if len(parts) != 3:
        return False
    area, group, serial = parts
    if area in ("000", "666") or area.startswith("9"):
        return False
    return group != "00" and serial != "0000"


VALIDATORS = {"luhn": luhn, "ssn_valid": ssn_valid}