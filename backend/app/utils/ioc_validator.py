"""IOC format validation utilities."""

import re
import ipaddress
from typing import Optional


# Regex patterns for IOC type detection
PATTERNS = {
    "ipv4": re.compile(
        r"^(?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}(?:25[0-5]|2[0-4]\d|[01]?\d\d?)$"
    ),
    "ipv6": re.compile(r"^(?:[0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}$"),
    "domain": re.compile(
        r"^(?:[a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$"
    ),
    "md5": re.compile(r"^[a-fA-F0-9]{32}$"),
    "sha1": re.compile(r"^[a-fA-F0-9]{40}$"),
    "sha256": re.compile(r"^[a-fA-F0-9]{64}$"),
    "url": re.compile(r"^https?://[^\s/$.?#].[^\s]*$", re.IGNORECASE),
    "email": re.compile(r"^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$"),
    "cve": re.compile(r"^CVE-\d{4}-\d{4,}$", re.IGNORECASE),
}


def detect_ioc_type(value: str) -> Optional[str]:
    """Auto-detect the type of an IOC value."""
    value = value.strip()

    if PATTERNS["cve"].match(value):
        return "cve"
    if PATTERNS["md5"].match(value):
        return "hash"
    if PATTERNS["sha1"].match(value):
        return "hash"
    if PATTERNS["sha256"].match(value):
        return "hash"
    if PATTERNS["email"].match(value):
        return "email"
    if PATTERNS["url"].match(value):
        return "url"

    # Check IP addresses
    try:
        addr = ipaddress.ip_address(value)
        return "ip"
    except ValueError:
        pass

    if PATTERNS["domain"].match(value):
        return "domain"

    return None


def validate_ioc(ioc_type: str, value: str) -> bool:
    """Validate an IOC value against its declared type."""
    value = value.strip()

    if ioc_type == "ip":
        try:
            ipaddress.ip_address(value)
            return True
        except ValueError:
            return False

    if ioc_type == "domain":
        return bool(PATTERNS["domain"].match(value))

    if ioc_type == "hash":
        return bool(
            PATTERNS["md5"].match(value)
            or PATTERNS["sha1"].match(value)
            or PATTERNS["sha256"].match(value)
        )

    if ioc_type == "url":
        return bool(PATTERNS["url"].match(value))

    if ioc_type == "email":
        return bool(PATTERNS["email"].match(value))

    if ioc_type == "cve":
        return bool(PATTERNS["cve"].match(value))

    return False


def get_hash_type(value: str) -> Optional[str]:
    """Determine the specific hash algorithm from a hash value."""
    value = value.strip()
    if PATTERNS["md5"].match(value):
        return "md5"
    if PATTERNS["sha1"].match(value):
        return "sha1"
    if PATTERNS["sha256"].match(value):
        return "sha256"
    return None


def normalize_ioc(value: str, ioc_type: str) -> str:
    """Normalize an IOC value for consistent storage."""
    value = value.strip()

    if ioc_type == "domain":
        value = value.lower().rstrip(".")
    elif ioc_type == "url":
        value = value.rstrip("/")
    elif ioc_type == "hash":
        value = value.lower()
    elif ioc_type == "email":
        value = value.lower()
    elif ioc_type == "ip":
        try:
            value = str(ipaddress.ip_address(value))
        except ValueError:
            pass
    elif ioc_type == "cve":
        value = value.upper()

    return value
