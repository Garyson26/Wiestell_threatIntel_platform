"""Helpers for stripping secrets out of text that leaves the process.

Exception strings from SQLAlchemy, httpx and smtplib routinely embed full
connection URIs (``mysql+aiomysql://user:password@host/db``) or API keys. Those
strings end up in API responses, persisted feed error columns and alert emails,
so they are redacted first.
"""

from __future__ import annotations

import re
from typing import Any, Dict, Iterable

# user:password@host  →  user:***@host  (covers any scheme)
_URI_CREDENTIALS = re.compile(r"(?P<scheme>[a-zA-Z0-9+.\-]+://)(?P<user>[^:/@\s]+):[^@/\s]+@")

# abuse.ch v2 bulk exports carry the Auth-Key as a URL *path segment*:
#   https://mb-api.abuse.ch/v2/files/exports/<AUTH-KEY>/recent.csv
#   https://urlhaus-api.abuse.ch/v2/files/exports/<AUTH-KEY>/payloads.csv
#
# Value-based redaction below covers keys this process has in its config. It does
# not cover a key it has never seen — a colleague's, an already-rotated one, or a
# test key an operator pasted into `feed_sources.url` by hand. That value would
# reach every viewer through FeedResponse, and every log line, unredacted.
#
# So match the *shape* as well: at these endpoints the segment after `/exports/`
# is a credential by construction.
#
# Anchored on an abuse.ch host, not on `/exports/` alone. A host-free pattern also
# rewrote indicator values — `http://evil.example/exports/report.pdf` came back as
# `/exports/***REDACTED***` — and IOC values do pass through this function inside
# error strings, so that would corrupt the very data an operator is reading. The
# trade is deliberate: if abuse.ch changes hostname this stops matching and only
# value-based redaction remains, which is a smaller failure than mangling IOCs.
_ABUSECH_EXPORT_KEY = re.compile(
    r"(?P<prefix>https?://[a-z0-9.\-]*abuse\.ch/(?:v\d+/)?(?:files/)?exports/)"
    r"(?P<key>[^/\s?#]{8,})",
    re.IGNORECASE,
)

REDACTED = "***REDACTED***"

# Request headers that must never be copied into logs or alert emails.
SENSITIVE_HEADERS = frozenset({
    "authorization",
    "proxy-authorization",
    "cookie",
    "set-cookie",
    "x-api-key",
    "x-cron-secret",
    "x-otx-api-key",
    "x-apikey",
    "auth-key",
    "key",
})


def _configured_secrets() -> Iterable[str]:
    """Secret values from settings that must never appear in outbound text."""
    from app.config import settings

    candidates = [
        settings.SECRET_KEY,
        settings.EMAIL_PASSWORD,
        settings.CRON_SECRET,
        settings.GROQ_API_KEY,
        settings.OTX_API_KEY,
        settings.ABUSEIPDB_API_KEY,
        settings.SHODAN_API_KEY,
        settings.MALWAREBAZAAR_API_KEY,
        settings.THREATFOX_API_KEY,
        settings.URLHAUS_API_KEY,
        settings.NVD_API_KEY,
        settings.YARAIFY_API_KEY,
        settings.CVEDETAILS_ACCESS_TOKEN,
        settings.DATABASE_URL,
        settings.DATABASE_ASYNC_URL,
    ]
    # Ignore short values: masking them would mangle unrelated text.
    return [c for c in candidates if c and len(c) >= 8]


def redact_secrets(text: Any) -> str:
    """Return ``text`` with connection credentials and known secrets masked."""
    if text is None:
        return ""
    result = str(text)
    result = _URI_CREDENTIALS.sub(rf"\g<scheme>\g<user>:{REDACTED}@", result)
    # Shape-based, so it covers keys this process does not know about.
    result = _ABUSECH_EXPORT_KEY.sub(rf"\g<prefix>{REDACTED}", result)
    for secret in _configured_secrets():
        if secret in result:
            result = result.replace(secret, REDACTED)
    return result


def redact_headers(headers: Dict[str, str]) -> Dict[str, str]:
    """Copy of ``headers`` with credential-bearing values masked."""
    return {
        name: (REDACTED if name.lower() in SENSITIVE_HEADERS else redact_secrets(value))
        for name, value in headers.items()
    }
