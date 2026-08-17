#!/usr/bin/env python
"""MANUAL GATE TOOL — sends a REAL email through the REAL Resend API. Not for deployment.

Spec 7 Section 5: the acceptance criterion for the SMTP -> Resend migration is a real OTP
delivered to a real inbox, because a mock proves nothing about blocked egress ports, domain
verification, or provider behaviour. This is that check.

bash / zsh:

    RESEND_API_KEY=re_xxx GATE_RECIPIENT=you@example.com \
        python scripts/gate_email_send.py

PowerShell (`VAR=value cmd` is a PARSE ERROR there, not a working variant):

    $env:RESEND_API_KEY = "re_xxx"
    $env:GATE_RECIPIENT = "you@example.com"
    python scripts/gate_email_send.py

The PowerShell form leaves the key in the session environment AND in the PSReadline history
file. Clear both afterwards:

    Remove-Item Env:RESEND_API_KEY
    # then delete the line from (Get-PSReadlineOption).HistorySavePath

This is exactly why the script takes no `--key` flag: a flag would put the key in shell
history as well, AND in the process table where any local user can read it with `ps`.
Reading from the environment keeps it out of the process table at least.

NOT IMPORTED BY ANYTHING AT RUNTIME. It lives in scripts/ beside the other operator tools
(seed_feeds, seed_mitre, rescore_corpus), none of which the application imports. It is a
`__main__` script with no importable side effects, so even an accidental import sends
nothing.

CREDENTIAL HANDLING, deliberate:
  * The key is read from the ENVIRONMENT ONLY. There is no default, no file fallback, no
    `.env` read, and no CLI flag - a flag would put the key in shell history and in the
    process table where any local user can read it via `ps`.
  * The key is NEVER printed. Not on success, not in an exception, not in a traceback.
    `httpx` exceptions can embed request context including headers, so every failure path
    below prints only the exception TYPE and a scrubbed message, never the exception's
    repr and never the request object.
  * Nothing is written to disk.

It sends to ONE recipient, once, with a fixed idempotency key derived from the run - so
re-running inside the 24-hour window returns the original response instead of sending a
second message and burning another of the 100 daily sends.
"""

import asyncio
import os
import sys
import time
import uuid

# The app package lives under backend/.
sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "backend"))


def _scrub(text: str, secret: str) -> str:
    """Last line of defence. Nothing below should contain the key, but assume it might."""
    if secret and secret in text:
        text = text.replace(secret, "[REDACTED]")
    return text


async def main() -> int:
    key = os.environ.get("RESEND_API_KEY", "").strip()
    recipient = os.environ.get("GATE_RECIPIENT", "").strip()

    if not key or not recipient:
        print("RESEND_API_KEY and GATE_RECIPIENT must both be set in the environment.")
        print("The gate cannot be satisfied with a mock — see the module docstring.")
        return 2

    # Configure the real settings object rather than reaching around it, so this exercises
    # exactly the code path production uses.
    os.environ.setdefault("DATABASE_URL", "mysql+pymysql://gate:gate@localhost/gate")
    os.environ.setdefault("SECRET_KEY", "gate-probe-key-not-used-for-anything-0000")

    from app.config import settings
    from app.utils import email_service

    settings.RESEND_API_KEY = key
    if os.environ.get("EMAIL_FROM"):
        settings.EMAIL_FROM = os.environ["EMAIL_FROM"]

    print(f"  from      : {settings.EMAIL_FROM}")
    print(f"  to        : {recipient}")
    print(f"  key       : present, {len(key)} chars (never printed)")

    # Capture the transport's own view so the response shape can be reported without the
    # sender having to return it. Wrapping rather than reimplementing: the request that
    # goes out is the one `send_otp_email` builds.
    import httpx

    seen = {}
    original = httpx.AsyncClient

    class _Observed(original):
        async def post(self, url, **kw):
            response = await super().post(url, **kw)
            seen["status"] = response.status_code
            seen["headers"] = {
                k: v for k, v in response.headers.items()
                if k.lower() in {"content-type", "ratelimit-limit", "ratelimit-remaining",
                                 "ratelimit-reset", "retry-after"}
            }
            try:
                seen["body"] = response.json()
            except Exception:
                seen["body"] = response.text[:300]
            return response

    httpx.AsyncClient = _Observed
    try:
        started = time.perf_counter()
        ok = await email_service.send_otp_email(
            recipient,
            "428913",
            "gate-test",
            idempotency_key=f"otp/gate/{uuid.uuid4()}",
        )
        elapsed_ms = (time.perf_counter() - started) * 1000
    except Exception as exc:
        # Type and scrubbed message only. Never repr(exc) - an httpx error can carry the
        # request, and the request carries the Authorization header.
        print(f"  EXCEPTION : {type(exc).__name__}: {_scrub(str(exc), key)[:200]}")
        return 1
    finally:
        httpx.AsyncClient = original

    print(f"  result    : {'SENT' if ok else 'FAILED'} in {elapsed_ms:.0f} ms")
    print(f"  status    : {seen.get('status')}")
    print(f"  headers   : {seen.get('headers')}")
    print(f"  body      : {_scrub(str(seen.get('body')), key)[:400]}")

    body = seen.get("body")
    if isinstance(body, dict) and body.get("name"):
        name = body["name"]
        message = str(body.get("message", ""))
        print(f"\n  ERROR NAME: {name}")
        if seen.get("status") == 403 and "testing emails" in message.lower():
            print("  STATE     : DOMAIN NOT VERIFIED. Resend restricts an unverified "
                  "domain to your own account address. This is a domain state, not a "
                  "code failure — retry with your own Resend account address to clear "
                  "the rest of the path.")
        elif name in {"daily_quota_exceeded", "monthly_quota_exceeded"}:
            print("  STATE     : quota exhausted; the degradation should now appear in "
                  "/cron-status.")
    elif ok:
        print("\n  Check the inbox. The gate needs the message to ARRIVE, not just a 200.")

    return 0 if ok else 1


if __name__ == "__main__":
    raise SystemExit(asyncio.run(main()))
