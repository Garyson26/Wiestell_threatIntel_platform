"""Email service for sending OTP and notifications.

Transport is the **Resend HTTP API over 443**, not SMTP. Render free web services cannot
open outbound connections on ports 25, 465 or 587, and the authentication flow is
password -> email OTP -> JWT, so without a transport over 443 nobody can log in at all,
including the owner. This is the gate on the project being testable, not a hardening task.

**Resend offers SMTP on 2465 and 2587, which Render does not block. That was considered and
rejected** (Spec 7 section 3): Render's block is anti-spam policy, so a port that merely
circumvents it can be closed without notice, and the HTTP API's structured error bodies are
what make quota exhaustion detectable at all - over SMTP a 4xx is opaque.

**The `resend` SDK is deliberately not used.** Its own FastAPI example calls
`resend.Emails.send()` from a synchronous endpoint, where FastAPI's threadpool hides the
blocking. This module is called from `async def` handlers, so the same call would block the
event loop on every OTP - the exact defect the original review found in `whois_enricher`.
`httpx` is already a dependency and adds no new advisory surface.

SECURITY PROPERTIES THAT MUST SURVIVE ANY CHANGE HERE (each has a test):
  * an OTP code is never logged and never returned, on any path including every failure;
  * delivery failure raises 503 for login and registration but is SWALLOWED for password
    reset - the asymmetry lives in `api/users.py::forgot_password` and exists so the
    endpoint is not an account-existence oracle (finding C-04);
  * an unconfigured transport returns False without attempting a request;
  * the username is HTML-escaped before rendering, and alert diagnostics go through
    `redact_secrets()` / `redact_headers()`;
  * alert email stays opt-in behind `ENABLE_ERROR_EMAILS`.
"""

import asyncio
import html
from datetime import datetime, timezone
from typing import Any, Dict, Optional, Tuple

import httpx
import structlog

from app.config import settings

logger = structlog.get_logger()

_API_URL = "https://api.resend.com/emails"

# A single POST. httpx's default timeout would let a hung provider hold a login request
# open far longer than a user will wait.
_TIMEOUT_SECONDS = 10.0


# ── Error classification ──────────────────────────────────────────────────────
# Verified against Resend's published error reference 2026-08-04, not from memory.
#
# STATUS ALONE IS NOT ENOUGH. Three distinct conditions return 429 and are separable only
# by the `name` field in the body, and only one of the three is retryable:
#
#   429 rate_limit_exceeded      too many requests per second   -> retry after backoff
#   429 daily_quota_exceeded     100/day cap on the free plan   -> NEVER retry, degrade
#   429 monthly_quota_exceeded   3,000/month                    -> NEVER retry, degrade
#
# `validation_error` is likewise ambiguous: the reference lists it at 400, 403 AND 422.
# The spec's table showed it only at 403. None of its forms is retryable, so the ambiguity
# costs nothing here - but it is why classification keys on (status, name) rather than
# either alone.

# The only responses worth trying a second time. Everything absent from this set is fatal.
_RETRYABLE_NAMES = frozenset({
    "rate_limit_exceeded",          # 429, transient by definition
    "concurrent_idempotent_requests",  # 409, the same key is still in flight
    "application_error",            # 500
    "internal_server_error",        # 500
})

# Recorded separately because these are not failures to retry but a state to SURFACE.
_QUOTA_NAMES = frozenset({"daily_quota_exceeded", "monthly_quota_exceeded"})

# OBSERVED on the live 200 response 2026-08-04, not documented in the error reference:
#
#   ratelimit-limit: 10      requests per second
#   ratelimit-remaining: 9
#   ratelimit-reset: 1       seconds until the window rolls
#
# So the `rate_limit_exceeded` threshold is READABLE per request rather than inferred, and
# the budget is 10/second. That is far above anything this application generates - an OTP
# is one request per login - so this is a cheap signal rather than a live problem.
#
# Backing off proactively when the remaining budget reaches zero is still worth doing: it
# converts a 429 plus a retry into a short wait, and it costs one header read. The threshold
# is 1 rather than 0 because the header reports the budget AFTER this request, so 0 means
# the next one is refused.
_RATELIMIT_REMAINING_HEADER = "ratelimit-remaining"
_RATELIMIT_RESET_HEADER = "ratelimit-reset"

# Never sleep longer than this on a proactive back-off. The reset window is one second, so
# a larger value means the header is reporting something unexpected and waiting on it would
# hold a login request open.
_MAX_BACKOFF_SECONDS = 2.0


def _is_retryable(status_code: int, name: str) -> bool:
    """Whether a second attempt could plausibly succeed.

    Deliberately allowlist-shaped. A denylist would make every unrecognised future error
    retryable, and the costly mistakes here are all in that direction - retrying a quota
    rejection burns the next window's allowance, and retrying `invalid_idempotent_request`
    means something regenerated the payload and a second send would be a DUPLICATE OTP.
    """
    if name == "invalid_idempotent_request":
        # 409, and never retryable: it means the retry rebuilt the payload, which for an
        # OTP means a different code. Retrying would deliver two codes for one login.
        return False
    if name in _QUOTA_NAMES:
        # REDUNDANT BY DESIGN, and verified so: the allowlist below already excludes these,
        # and `_post` returns before ever consulting this function for a quota name. A
        # mutation removing this line changed no behaviour. It stays as a second barrier -
        # if someone later adds a quota name to _RETRYABLE_NAMES by mistake, this still
        # catches it, and retrying a quota rejection burns the next window's allowance.
        return False
    if name in _RETRYABLE_NAMES:
        return True
    # No name (a proxy error page, a truncated body) - fall back to the status class.
    # 5xx is provider-side and worth one more attempt; every 4xx is our fault.
    return not name and status_code >= 500


# ── Quota state (Section 2) ───────────────────────────────────────────────────
# PROCESS-LOCAL, which is correct only under the single-process model. This is now the
# SIXTH thing that assumption governs, alongside the rate limiter, the connection pool,
# the enrichment semaphore, any in-process cache, and REDIS_URL being unset. See the
# invariant in CLAUDE.md; raising the worker count means N independent views of quota, so
# a cap hit by one worker would be invisible to the others.
_quota_state: Dict[str, Optional[datetime]] = {
    "daily_quota_exceeded": None,
    "monthly_quota_exceeded": None,
}


def _record_quota_rejection(name: str) -> None:
    _quota_state[name] = datetime.now(timezone.utc)
    logger.error(
        "email_quota_exceeded",
        quota=name,
        detail=(
            "Resend rejected the send because the plan quota is exhausted. OTP delivery "
            "is failing, which means login and registration return 503 and password reset "
            "silently does nothing."
        ),
    )


def quota_degradation() -> Optional[Dict[str, str]]:
    """The `email_quota_exhausted` entry for /cron-status, or None.

    Reported by elapsed time rather than by a flag, so it clears itself: the daily cap
    resets every 24 hours and the monthly one at the calendar month. Without that, a single
    rejection would leave the degradation showing for the life of the process.
    """
    now = datetime.now(timezone.utc)

    daily = _quota_state.get("daily_quota_exceeded")
    if daily is not None and (now - daily).total_seconds() < 24 * 3600:
        return {
            "id": "email_quota_exhausted",
            "impact": (
                "the Resend daily cap (100/day on the free plan) was hit at "
                f"{daily.isoformat()}; OTP delivery is failing, so login and registration "
                "return 503 and password reset silently does nothing"
            ),
            "fix": (
                "wait for the daily reset, or raise the plan. Every tester logs in at "
                "least twice a day because JWT expiry is 12 hours, so 100/day is the limit "
                "this deployment actually reaches."
            ),
        }

    monthly = _quota_state.get("monthly_quota_exceeded")
    if monthly is not None and (monthly.year, monthly.month) == (now.year, now.month):
        return {
            "id": "email_quota_exhausted",
            "impact": (
                "the Resend monthly cap (3,000/month on the free plan) was hit at "
                f"{monthly.isoformat()}; no email will send until the calendar month rolls"
            ),
            "fix": "raise the plan; sending pauses at the cap rather than billing overage",
        }
    return None


def _reset_quota_state_for_tests() -> None:
    """Test hook. Module-level state would otherwise leak between tests."""
    for key in _quota_state:
        _quota_state[key] = None


# ── Transport ─────────────────────────────────────────────────────────────────

def _configured() -> bool:
    return bool(settings.RESEND_API_KEY and settings.EMAIL_FROM)


def _parse_error(response: httpx.Response) -> Tuple[str, str]:
    """(name, message) from an error body, tolerating a non-JSON response.

    A proxy or gateway in front of the API can return HTML, so this must never raise -
    a parse failure would surface as a 500 from the login endpoint rather than a clean 503.
    """
    try:
        body = response.json()
    except Exception:
        return "", response.text[:200]
    if not isinstance(body, dict):
        return "", str(body)[:200]
    return str(body.get("name") or ""), str(body.get("message") or "")[:300]


async def _respect_rate_limit(response: "httpx.Response") -> None:
    """Wait out the window when the response says the next request would be refused.

    Resend reports the per-second budget on every response (observed: limit 10, and a
    one-second reset). Reading it turns a 429-then-retry into a short wait, which matters
    only under burst - at OTP volume the budget is never approached - but it is one header
    read and it makes the retry more likely to succeed rather than merely repeated.

    Silent on anything unexpected: a missing, non-numeric or implausibly large value means
    the contract changed, and guessing would hold a login request open.
    """
    remaining = response.headers.get(_RATELIMIT_REMAINING_HEADER)
    if remaining is None:
        return
    try:
        if int(remaining) > 0:
            return
        wait = float(response.headers.get(_RATELIMIT_RESET_HEADER, 1))
    except (TypeError, ValueError):
        return
    if 0 < wait <= _MAX_BACKOFF_SECONDS:
        logger.info("email_rate_limit_backoff", seconds=wait)
        await asyncio.sleep(wait)


async def _post(payload: Dict[str, Any], idempotency_key: Optional[str]) -> bool:
    """POST one prepared payload, with at most one retry. Never raises.

    THE PAYLOAD AND THE KEY ARE BUILT BY THE CALLER AND NOT REBUILT HERE. That is the whole
    point of taking them as arguments: a retry must send BYTE-IDENTICAL content under the
    SAME idempotency key. For an OTP the code lives inside the payload, so regenerating it
    on retry would both change the bytes - earning `409 invalid_idempotent_request` - and,
    worse, deliver a second, different code for one login attempt.
    """
    if not _configured():
        logger.error(
            "email_not_configured",
            hint="Set RESEND_API_KEY and EMAIL_FROM",
        )
        return False

    headers = {
        "Authorization": f"Bearer {settings.RESEND_API_KEY}",
        "Content-Type": "application/json",
    }
    if idempotency_key:
        # Resend keeps a key for 24 hours; a repeat inside that window returns the original
        # response without sending again. Max 256 characters (400 invalid_idempotency_key
        # outside 1-256), so the key is truncated defensively rather than trusted.
        headers["Idempotency-Key"] = idempotency_key[:256]

    # One attempt, then at most one retry. Two is enough to ride out a transient 5xx or a
    # concurrent-key collision; more would hold a login request open past a user's patience.
    for attempt in (1, 2):
        try:
            async with httpx.AsyncClient(timeout=_TIMEOUT_SECONDS) as client:
                response = await client.post(_API_URL, json=payload, headers=headers)
        except httpx.HTTPError as exc:
            # Connection-level: no response, so nothing to classify. The idempotency key
            # makes a retry safe even if the first request did arrive.
            if attempt == 1:
                logger.warning("email_send_retrying", reason=type(exc).__name__)
                continue
            logger.error("email_send_failed", error_type=type(exc).__name__)
            return False

        if response.is_success:
            return True

        name, message = _parse_error(response)

        if name in _QUOTA_NAMES:
            _record_quota_rejection(name)
            return False

        if _is_retryable(response.status_code, name) and attempt == 1:
            logger.warning(
                "email_send_retrying", status=response.status_code, name=name or "unknown"
            )
            await _respect_rate_limit(response)
            continue

        # `message` can name a domain or an address, so it is logged but never returned to
        # a caller - the 503 that reaches the client stays generic.
        logger.error(
            "email_send_failed",
            status=response.status_code,
            name=name or "unknown",
            detail=message,
        )
        return False

    return False


async def send_otp_email(
    to_email: str,
    otp: str,
    username: str,
    is_password_reset: bool = False,
    idempotency_key: Optional[str] = None,
) -> bool:
    """
    Send OTP via email using SMTP.
    
    Args:
        to_email: Recipient email address
        otp: The OTP code to send
        username: Username of the recipient
        is_password_reset: Whether this is for password reset (default: False)
        
    Returns:
        True if email sent successfully, False otherwise
    """
    if not _configured():
        logger.error("email_not_configured", hint="Set RESEND_API_KEY and EMAIL_FROM")
        return False

    # The username is rendered inside an HTML email — escape it so a crafted
    # display name cannot inject markup into the message body.
    username = html.escape(username or "", quote=True)

    try:
        # Create message
        if is_password_reset:
            subject = "Wiestell - Password Reset OTP"
            purpose = "password reset"
            expiry = "10 minutes"
        else:
            subject = "Wiestell - Your Login OTP Code"
            purpose = "login"
            expiry = "5 minutes"
            

        # Create HTML and plain text versions
        text_content = f"""
Hello {username},

Your OTP code for {purpose} on Wiestell Threat Intelligence Platform is: {otp}

This code will expire in {expiry}.

If you did not request this code, please ignore this email.

Best regards,
Wiestell Security Team
"""

        html_content = f"""
<!DOCTYPE html>
<html>
<head>
    <style>
        body {{
            font-family: 'Courier New', monospace;
            background-color: #0a0e1a;
            color: #e5e7eb;
            padding: 20px;
        }}
        .container {{
            max-width: 600px;
            margin: 0 auto;
            background-color: #151b2e;
            border: 1px solid #00d9ff;
            border-radius: 8px;
            padding: 30px;
        }}
        .header {{
            text-align: center;
            color: #00d9ff;
            font-size: 24px;
            font-weight: bold;
            margin-bottom: 20px;
            letter-spacing: 2px;
        }}
        .otp-box {{
            background-color: #1a2332;
            border: 2px solid #00d9ff;
            border-radius: 8px;
            padding: 20px;
            text-align: center;
            margin: 20px 0;
        }}
        .otp-code {{
            font-size: 36px;
            font-weight: bold;
            color: #00d9ff;
            letter-spacing: 8px;
            margin: 10px 0;
        }}
        .message {{
            color: #9ca3af;
            font-size: 14px;
            line-height: 1.6;
            margin: 15px 0;
        }}
        .warning {{
            color: #fbbf24;
            font-size: 12px;
            margin-top: 20px;
            text-align: center;
        }}
        .footer {{
            text-align: center;
            color: #6b7280;
            font-size: 11px;
            margin-top: 30px;
            padding-top: 20px;
            border-top: 1px solid #374151;
        }}
    </style>
</head>
<body>
    <div class="container">
        <div class="header">🛡️ Wiestell</div>
        <p class="message">Hello <strong>{username}</strong>,</p>
        <p class="message">Your OTP code for <strong>{purpose}</strong> on Wiestell Threat Intelligence Platform:</p>
        
        <div class="otp-box">
            <div class="otp-code">{otp}</div>
        </div>
        
        <p class="message">This code will expire in <strong>{expiry}</strong>.</p>
        <p class="warning">⚠️ If you did not request this code, please ignore this email.</p>
        
        <div class="footer">
            © 2026 Wiestell Threat Intelligence Platform<br>
            This is an automated message. Please do not reply.
        </div>
    </div>
</body>
</html>
"""

        # Attach both versions
        # Built ONCE, before the first attempt. `_post` retries this exact object so a
        # retry cannot deliver a different code - see its docstring.
        payload = {
            "from": settings.EMAIL_FROM,
            "to": [to_email],
            "subject": subject,
            "html": html_content,
            "text": text_content,
        }
        if not await _post(payload, idempotency_key):
            return False

        # The recipient address and the code itself are deliberately absent from
        # the log line — an OTP in a log file is a bypass of the second factor.
        logger.info("otp_email_sent", is_password_reset=is_password_reset)
        return True

    except Exception as e:
        logger.error("otp_email_failed", error_type=type(e).__name__, error=str(e))
        return False


async def send_notification_email(to_email: str, subject: str, message: str) -> bool:
    """
    Send a generic notification email.
    
    Args:
        to_email: Recipient email address
        subject: Email subject
        message: Email message content
        
    Returns:
        True if email sent successfully, False otherwise
    """
    if not _configured():
        logger.error("email_not_configured")
        return False

    try:
        if not await _post({
            "from": settings.EMAIL_FROM,
            "to": [to_email],
            "subject": subject,
            "text": message,
        }, None):
            return False

        logger.info("notification_email_sent")
        return True

    except Exception as e:
        logger.error("notification_email_failed", error_type=type(e).__name__, error=str(e))
        return False


async def send_error_alert_email(
    error_type: str,
    error_message: str,
    endpoint: str,
    method: str,
    traceback_info: str,
    request_data: Optional[dict] = None
) -> bool:
    """
    Send error alert email to admin.
    
    Args:
        error_type: Type of error (e.g., "500 Internal Server Error")
        error_message: Error message
        endpoint: API endpoint where error occurred
        method: HTTP method (GET, POST, etc.)
        traceback_info: Traceback information
        request_data: Optional request data for debugging
        
    Returns:
        True if email sent successfully, False otherwise
    """
    if not settings.ENABLE_ERROR_EMAILS or not settings.ADMIN_EMAIL or not _configured():
        return False

    # Diagnostics are embedded in an HTML email; escape them so error text
    # containing markup cannot inject content into the admin's mail client.
    error_type = html.escape(str(error_type))
    error_message = html.escape(str(error_message))
    endpoint = html.escape(str(endpoint))
    method = html.escape(str(method))
    traceback_info = html.escape(str(traceback_info))
    safe_request_data = html.escape(str(request_data)) if request_data else None

    try:
        from datetime import datetime
        timestamp = datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S UTC")

        # Create message
        subject = f"🚨 Wiestell API Error: {error_type}"

        # Create plain text version
        text_content = f"""
🚨 ERROR ALERT - Wiestell Threat Intelligence Platform

Timestamp: {timestamp}
Error Type: {error_type}
Endpoint: {method} {endpoint}

Error Message:
{error_message}

Traceback:
{traceback_info}

Request Data:
{request_data if request_data else "N/A"}

---
This is an automated alert from Wiestell API monitoring.
"""

        # Create HTML version
        html_content = f"""
<!DOCTYPE html>
<html>
<head>
    <style>
        body {{
            font-family: 'Courier New', monospace;
            background-color: #0a0e1a;
            color: #e5e7eb;
            padding: 20px;
        }}
        .container {{
            max-width: 800px;
            margin: 0 auto;
            background-color: #151b2e;
            border: 2px solid #ef4444;
            border-radius: 8px;
            padding: 30px;
        }}
        .header {{
            text-align: center;
            color: #ef4444;
            font-size: 24px;
            font-weight: bold;
            margin-bottom: 20px;
        }}
        .error-box {{
            background-color: #1a2332;
            border-left: 4px solid #ef4444;
            padding: 15px;
            margin: 15px 0;
        }}
        .info-row {{
            margin: 10px 0;
            padding: 8px;
            background-color: #0f1419;
            border-radius: 4px;
        }}
        .label {{
            color: #00d9ff;
            font-weight: bold;
            display: inline-block;
            width: 150px;
        }}
        .value {{
            color: #e5e7eb;
        }}
        .traceback {{
            background-color: #0f1419;
            border: 1px solid #374151;
            border-radius: 4px;
            padding: 15px;
            margin: 15px 0;
            overflow-x: auto;
            font-size: 12px;
            color: #fbbf24;
        }}
        .footer {{
            text-align: center;
            color: #6b7280;
            font-size: 11px;
            margin-top: 30px;
            padding-top: 20px;
            border-top: 1px solid #374151;
        }}
    </style>
</head>
<body>
    <div class="container">
        <div class="header">🚨 API ERROR ALERT</div>
        
        <div class="info-row">
            <span class="label">Timestamp:</span>
            <span class="value">{timestamp}</span>
        </div>
        
        <div class="info-row">
            <span class="label">Error Type:</span>
            <span class="value">{error_type}</span>
        </div>
        
        <div class="info-row">
            <span class="label">Endpoint:</span>
            <span class="value">{method} {endpoint}</span>
        </div>
        
        <div class="error-box">
            <strong style="color: #ef4444;">Error Message:</strong><br>
            <p style="margin: 10px 0; color: #fbbf24;">{error_message}</p>
        </div>
        
        <div class="traceback">
            <strong>Traceback:</strong><br>
            <pre style="margin: 10px 0; white-space: pre-wrap;">{traceback_info}</pre>
        </div>
        
        {f'<div class="info-row"><span class="label">Request Data:</span><br><pre style="margin: 10px 0; color: #9ca3af;">{safe_request_data}</pre></div>' if safe_request_data else ''}
        
        <div class="footer">
            Wiestell Threat Intelligence Platform - Automated Error Monitoring<br>
            This is an automated alert. Check server logs for more details.
        </div>
    </div>
</body>
</html>
"""

        # Attach both versions
        if not await _post({
            "from": settings.EMAIL_FROM,
            "to": [settings.ADMIN_EMAIL],
            "subject": subject,
            "html": html_content,
            "text": text_content,
        }, None):
            return False

        logger.info("error_alert_email_sent")
        return True

    except Exception as e:
        # Don't let email failures cause additional errors
        logger.warning("error_alert_email_failed", error_type=type(e).__name__)
        return False
