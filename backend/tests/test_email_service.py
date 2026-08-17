"""Email transport over the Resend HTTP API (Phase 3, replacing SMTP).

Render free web services cannot reach ports 25/465/587, and the auth flow is
password -> email OTP -> JWT, so this transport is the gate on anyone being able to log in.

The security properties asserted here are findings from the original review, not
implementation preferences. Each survived the SMTP -> HTTP migration and must keep
surviving.
"""

import asyncio
import json
import threading

import httpx
import pytest

from app.config import settings
from app.utils import email_service
from app.utils.email_service import (
    _is_retryable,
    _reset_quota_state_for_tests,
    quota_degradation,
    send_error_alert_email,
    send_otp_email,
)

OTP_CODE = "428913"


@pytest.fixture(autouse=True)
def _clean_quota_state():
    _reset_quota_state_for_tests()
    yield
    _reset_quota_state_for_tests()


@pytest.fixture
def configured(monkeypatch):
    monkeypatch.setattr(settings, "RESEND_API_KEY", "re_test_key_000000000000")
    monkeypatch.setattr(settings, "EMAIL_FROM", "Wiestell <noreply@wiestell.com>")


class _Transport:
    """Records every request and replays a scripted sequence of responses."""

    def __init__(self, *responses):
        self.responses = list(responses)
        self.requests = []

    def install(self, monkeypatch):
        outer = self

        class _Client:
            def __init__(self, *a, **kw):
                outer.client_kwargs = kw

            async def __aenter__(self):
                return self

            async def __aexit__(self, *exc):
                return False

            async def post(self, url, json=None, headers=None):
                outer.requests.append(
                    {"url": url, "json": json, "headers": dict(headers or {})}
                )
                nxt = outer.responses.pop(0) if outer.responses else outer.last
                outer.last = nxt
                if isinstance(nxt, Exception):
                    raise nxt
                return nxt

        monkeypatch.setattr(httpx, "AsyncClient", _Client)
        return self

    @property
    def attempts(self):
        return len(self.requests)


def _response(status, body=None):
    return httpx.Response(
        status_code=status,
        content=json.dumps(body if body is not None else {"id": "email-id-123"}),
        headers={"content-type": "application/json"},
        request=httpx.Request("POST", "https://api.resend.com/emails"),
    )


# ── §1.4 error classification ────────────────────────────────────────────────

class TestErrorClassification:
    """Every row of the spec's table, verified against Resend's published reference.

    Status alone is insufficient: THREE conditions return 429 and only the `name` field
    separates them, and only one of the three may be retried.
    """

    @pytest.mark.parametrize("status,name,retryable", [
        # The three 429s - the reason classification cannot key on status alone.
        (429, "rate_limit_exceeded", True),
        (429, "daily_quota_exceeded", False),
        (429, "monthly_quota_exceeded", False),
        # Auth and configuration - never retryable.
        (401, "missing_api_key", False),
        (401, "restricted_api_key", False),
        (403, "invalid_api_key", False),
        (403, "validation_error", False),
        (422, "invalid_from_address", False),
        (422, "missing_required_field", False),
        # Idempotency.
        (409, "invalid_idempotent_request", False),
        (409, "concurrent_idempotent_requests", True),
        (400, "invalid_idempotency_key", False),
        # Other.
        (451, "security_error", False),
        (500, "application_error", True),
        (500, "internal_server_error", True),
    ])
    def test_each_documented_error_maps_to_the_right_retry_decision(
        self, status, name, retryable
    ):
        assert _is_retryable(status, name) is retryable, (
            f"{status} {name} classified wrongly"
        )

    @pytest.mark.parametrize("status,name", [
        # OBSERVED AGAINST THE LIVE API 2026-08-04, and it contradicts Resend's own
        # published reference. The docs list an invalid key as `403 invalid_api_key`;
        # the live API returns `401 validation_error` with message "API key is invalid".
        # Both are non-retryable so the classifier is correct either way - but the row is
        # pinned against what the API ACTUALLY returns rather than what it documents,
        # because that is the shape production will see.
        (401, "validation_error"),
        (401, "missing_api_key"),      # matches the docs
        (403, "invalid_api_key"),      # documented shape, kept in case it returns
    ])
    def test_the_observed_auth_failures_are_not_retried(self, status, name):
        assert _is_retryable(status, name) is False

    def test_invalid_idempotent_request_is_never_retried(self):
        """409 with a different payload means something REGENERATED the content.

        For an OTP that means a different code, so a retry would deliver two codes for one
        login attempt. Retrying is worse than failing.
        """
        assert _is_retryable(409, "invalid_idempotent_request") is False

    def test_an_unnamed_5xx_is_retryable_and_an_unnamed_4xx_is_not(self):
        """A proxy error page carries no `name`, so status is the only signal left."""
        assert _is_retryable(502, "") is True
        assert _is_retryable(400, "") is False

    @pytest.mark.parametrize("status,name", [
        (429, "some_future_error"),
        (418, "teapot"),
        (500, "brand_new_5xx_name"),   # a NAMED 5xx is still not retried
        (503, "unknown"),
        (400, "whatever"),
    ])
    def test_any_unrecognised_NAME_fails_closed(self, status, name):
        """The default matters more than any single row.

        The 401/403 discrepancy found against the live API proves the published reference
        is wrong somewhere, so the behaviour for combinations NOT in the table is the thing
        that has to be right. Unknown means do not retry - including a named 5xx, which is
        the conservative direction on purpose: the cost of not retrying is one failed login
        the user can repeat, while wrongly retrying can burn quota or duplicate a send.
        """
        assert _is_retryable(status, name) is False

    @pytest.mark.parametrize("status,retryable", [
        (500, True), (502, True), (504, True),
        (400, False), (403, False), (429, False),
    ])
    def test_a_BODYLESS_response_falls_back_to_the_status_class(self, status, retryable):
        """The one opt-in that is NOT the allowlist, stated plainly rather than hidden.

        A CDN or gateway can return an HTML error page with no `name` to allowlist. Not
        retrying those would let a transient 502 fail a login. So there are exactly two
        ways to be retryable: be on the allowlist, or have NO name and a 5xx status. Any
        third path appearing here is a bug.
        """
        assert _is_retryable(status, "") is retryable

    def test_an_unknown_name_is_not_retried(self):
        """Allowlist-shaped: a future error must not become retryable by default."""
        assert _is_retryable(429, "some_future_error") is False


# ── Retry and idempotency ────────────────────────────────────────────────────

class TestRetryAndIdempotency:
    async def test_a_retry_resends_a_byte_identical_payload_and_the_same_key(
        self, configured, monkeypatch
    ):
        """The payload must NOT be rebuilt between attempts.

        The OTP code lives inside the payload. Rebuilding it would change the bytes -
        earning 409 invalid_idempotent_request - and would deliver a second, different code.
        """
        transport = _Transport(
            _response(500, {"name": "application_error", "message": "boom"}),
            _response(200),
        ).install(monkeypatch)

        assert await send_otp_email(
            "a@example.com", OTP_CODE, "alice", idempotency_key="otp/login/row-1"
        ) is True
        assert transport.attempts == 2

        first, second = transport.requests
        assert first["json"] == second["json"], "the payload was rebuilt between attempts"
        assert first["headers"]["Idempotency-Key"] == "otp/login/row-1"
        assert second["headers"]["Idempotency-Key"] == "otp/login/row-1"

    async def test_at_most_one_retry(self, configured, monkeypatch):
        transport = _Transport(
            _response(500, {"name": "application_error"}),
            _response(500, {"name": "application_error"}),
            _response(200),
        ).install(monkeypatch)
        assert await send_otp_email("a@example.com", OTP_CODE, "alice") is False
        assert transport.attempts == 2, "more than one retry was attempted"

    @pytest.mark.parametrize("name", [
        "daily_quota_exceeded", "monthly_quota_exceeded", "invalid_api_key",
        "invalid_from_address", "invalid_idempotent_request", "security_error",
    ])
    async def test_fatal_errors_are_not_retried(self, configured, monkeypatch, name):
        status = 429 if "quota" in name else 403
        transport = _Transport(_response(status, {"name": name}),
                               _response(200)).install(monkeypatch)
        assert await send_otp_email("a@example.com", OTP_CODE, "alice") is False
        assert transport.attempts == 1, f"{name} was retried"

    async def test_a_connection_error_is_retried_once(self, configured, monkeypatch):
        transport = _Transport(
            httpx.ConnectError("refused"), _response(200)
        ).install(monkeypatch)
        assert await send_otp_email("a@example.com", OTP_CODE, "alice") is True
        assert transport.attempts == 2

    async def test_the_key_is_truncated_to_the_documented_maximum(
        self, configured, monkeypatch
    ):
        """Resend returns 400 invalid_idempotency_key outside 1-256 characters."""
        transport = _Transport(_response(200)).install(monkeypatch)
        await send_otp_email("a@example.com", OTP_CODE, "alice",
                             idempotency_key="x" * 400)
        assert len(transport.requests[0]["headers"]["Idempotency-Key"]) == 256

    async def test_a_timeout_is_set(self, configured, monkeypatch):
        """httpx's default would let a hung provider hold a login request open."""
        transport = _Transport(_response(200)).install(monkeypatch)
        await send_otp_email("a@example.com", OTP_CODE, "alice")
        assert transport.client_kwargs.get("timeout") == 10.0


# ── §1.2 security properties ─────────────────────────────────────────────────

class TestTheOtpCodeNeverEscapes:
    """An OTP in a log file is a bypass of the second factor."""

    @pytest.mark.parametrize("status,body", [
        (200, {"id": "x"}),
        (403, {"name": "invalid_api_key", "message": "bad key"}),
        (429, {"name": "daily_quota_exceeded", "message": "cap"}),
        (500, {"name": "application_error", "message": "boom"}),
    ])
    async def test_the_code_appears_in_no_log_on_any_path(
        self, configured, monkeypatch, capsys, status, body
    ):
        _Transport(_response(status, body), _response(status, body)).install(monkeypatch)
        await send_otp_email("victim@example.com", OTP_CODE, "alice")
        out = capsys.readouterr()
        combined = out.out + out.err
        assert OTP_CODE not in combined, f"the OTP leaked into logs on status {status}"
        assert "victim@example.com" not in combined, "the address leaked into logs"

    async def test_a_connection_failure_does_not_log_the_code(
        self, configured, monkeypatch, capsys
    ):
        _Transport(httpx.ConnectError("x"), httpx.ConnectError("x")).install(monkeypatch)
        await send_otp_email("victim@example.com", OTP_CODE, "alice")
        combined = "".join(capsys.readouterr())
        assert OTP_CODE not in combined


class TestConfigurationGate:
    async def test_an_unconfigured_key_returns_false_without_a_request(
        self, monkeypatch
    ):
        monkeypatch.setattr(settings, "RESEND_API_KEY", "")
        transport = _Transport(_response(200)).install(monkeypatch)
        assert await send_otp_email("a@example.com", OTP_CODE, "alice") is False
        assert transport.attempts == 0, "a request was made with no API key"


class TestRenderedBody:
    async def test_the_username_is_html_escaped(self, configured, monkeypatch):
        """A crafted display name must not inject markup into the message body."""
        transport = _Transport(_response(200)).install(monkeypatch)
        await send_otp_email("a@example.com", OTP_CODE, "<script>alert(1)</script>")
        body = transport.requests[0]["json"]["html"]
        assert "<script>alert(1)</script>" not in body
        assert "&lt;script&gt;" in body

    async def test_the_payload_shape_matches_the_api(self, configured, monkeypatch):
        transport = _Transport(_response(200)).install(monkeypatch)
        await send_otp_email("a@example.com", OTP_CODE, "alice")
        payload = transport.requests[0]["json"]
        assert payload["from"] == "Wiestell <noreply@wiestell.com>"
        assert payload["to"] == ["a@example.com"], "`to` must be a list"
        assert payload["subject"] and payload["html"]
        assert transport.requests[0]["url"] == "https://api.resend.com/emails"
        assert transport.requests[0]["headers"]["Authorization"].startswith("Bearer ")


class TestAlertEmailStaysOptIn:
    async def test_inert_when_disabled(self, configured, monkeypatch):
        monkeypatch.setattr(settings, "ENABLE_ERROR_EMAILS", False)
        monkeypatch.setattr(settings, "ADMIN_EMAIL", "admin@example.com")
        transport = _Transport(_response(200)).install(monkeypatch)
        assert await send_error_alert_email("500", "m", "/e", "GET", "tb") is False
        assert transport.attempts == 0

    async def test_sends_when_enabled(self, configured, monkeypatch):
        monkeypatch.setattr(settings, "ENABLE_ERROR_EMAILS", True)
        monkeypatch.setattr(settings, "ADMIN_EMAIL", "admin@example.com")
        transport = _Transport(_response(200)).install(monkeypatch)
        assert await send_error_alert_email("500", "m", "/e", "GET", "tb") is True
        assert transport.requests[0]["json"]["to"] == ["admin@example.com"]


# ── §2 quota degradation ─────────────────────────────────────────────────────

class TestQuotaDegradation:
    """Quota exhaustion surfaces as a 503 on login and as NOTHING on password reset.

    From outside that looks like a server bug, and the daily reset makes it appear to fix
    itself. So it has to be a named, visible state rather than a log line.
    """

    def test_nothing_is_reported_when_no_quota_was_hit(self):
        assert quota_degradation() is None

    async def test_a_daily_rejection_sets_the_degradation(self, configured, monkeypatch):
        _Transport(_response(429, {"name": "daily_quota_exceeded"})).install(monkeypatch)
        await send_otp_email("a@example.com", OTP_CODE, "alice")

        entry = quota_degradation()
        assert entry is not None
        assert entry["id"] == "email_quota_exhausted"
        assert entry["impact"] and entry["fix"], "an id alone is not actionable"

    async def test_a_monthly_rejection_sets_it_too(self, configured, monkeypatch):
        _Transport(_response(429, {"name": "monthly_quota_exceeded"})).install(monkeypatch)
        await send_otp_email("a@example.com", OTP_CODE, "alice")
        assert quota_degradation() is not None

    def test_the_daily_state_clears_after_24_hours(self, monkeypatch):
        """Reported by elapsed time, so it clears itself when the cap resets."""
        from datetime import datetime, timedelta, timezone

        stale = datetime.now(timezone.utc) - timedelta(hours=25)
        monkeypatch.setitem(email_service._quota_state, "daily_quota_exceeded", stale)
        assert quota_degradation() is None

    def test_the_daily_state_is_still_reported_within_24_hours(self, monkeypatch):
        from datetime import datetime, timedelta, timezone

        recent = datetime.now(timezone.utc) - timedelta(hours=23)
        monkeypatch.setitem(email_service._quota_state, "daily_quota_exceeded", recent)
        assert quota_degradation() is not None

    async def test_it_reaches_the_admin_degradations_array(self, configured, monkeypatch):
        """Wired into /cron-status alongside the GeoIP and worker states."""
        from app.enrichers import reset_registry
        from app.main import _deployment_degradations

        _Transport(_response(429, {"name": "daily_quota_exceeded"})).install(monkeypatch)
        await send_otp_email("a@example.com", OTP_CODE, "alice")
        reset_registry()

        ids = {d["id"] for d in _deployment_degradations()}
        assert "email_quota_exhausted" in ids, (
            f"quota exhaustion is invisible in /cron-status. Got: {ids}"
        )


# ── Event loop ───────────────────────────────────────────────────────────────

class TestTheSendPathDoesNotBlockTheLoop:
    """Mirrors the WHOIS off-loop test.

    The `resend` SDK was rejected precisely because its synchronous call would block here -
    every OTP would stall the whole event loop for the duration of an HTTP round trip.
    """

    async def test_the_loop_stays_responsive_during_a_send(self, configured, monkeypatch):
        release = threading.Event()
        sending_thread = {}

        class _Slow:
            def __init__(self, *a, **kw):
                pass

            async def __aenter__(self):
                return self

            async def __aexit__(self, *exc):
                return False

            async def post(self, url, json=None, headers=None):
                sending_thread["id"] = threading.get_ident()
                await asyncio.sleep(0.05)
                return _response(200)

        monkeypatch.setattr(httpx, "AsyncClient", _Slow)

        ticks = 0

        async def _ticker():
            nonlocal ticks
            for _ in range(5):
                await asyncio.sleep(0.005)
                ticks += 1

        send = asyncio.create_task(
            send_otp_email("a@example.com", OTP_CODE, "alice")
        )
        tick = asyncio.create_task(_ticker())
        assert await send is True
        await tick

        assert ticks == 5, (
            "the event loop was blocked during the send - other requests would have "
            "stalled for the duration of the HTTP round trip"
        )

    def test_the_public_senders_are_coroutines(self):
        """A sync def here would be run in a threadpool by FastAPI and hide the blocking."""
        import inspect

        for fn in (email_service.send_otp_email,
                   email_service.send_notification_email,
                   email_service.send_error_alert_email):
            assert inspect.iscoroutinefunction(fn), f"{fn.__name__} is not async"


class TestTheKeyIsNotAFeedCredential:
    """RESEND_API_KEY must never be dereferenceable from a feed row.

    `ALLOWED_FEED_API_KEY_ENVS` is the H-03 exfiltration surface: a name on it can be
    referenced by `feed.api_key_env` and forwarded to a third-party endpoint. This is a
    service credential for our own outbound mail, not a feed credential.
    """

    def test_it_is_absent_from_the_allowlist(self):
        from app.config import ALLOWED_FEED_API_KEY_ENVS

        assert "RESEND_API_KEY" not in ALLOWED_FEED_API_KEY_ENVS

    def test_the_schema_rejects_it(self):
        from pydantic import ValidationError

        from app.schemas.feed import FeedCreate

        with pytest.raises(ValidationError):
            FeedCreate(
                name="x", slug="x", url="https://e.example",
                feed_type="ip", api_key_env="RESEND_API_KEY",
            )


class TestC04PasswordResetMustNotBecomeAnAccountExistenceOracle:
    """The asymmetry in §1.2, guarded where the property actually lives.

    `_issue_otp` raises 503 on delivery failure and login/registration let it through.
    `forgot_password` CATCHES it. That try/except looks like defensive tidying, and it is
    not: a 503 is only ever raised for an address that EXISTS, because an address with no
    account never reaches `_issue_otp`. A visible error therefore distinguishes "real
    account, mail failed" from "no such account" - which is finding C-04.

    The class is named for the consequence rather than the mechanism so that a failure
    reads as "you reintroduced the oracle", not "a try/except changed".
    """

    def test_the_reset_endpoint_still_swallows_delivery_failure(self):
        import inspect

        from app.api import users

        source = inspect.getsource(users.forgot_password)
        assert "except HTTPException" in source, (
            "forgot_password no longer catches the 503 from _issue_otp. That reintroduces "
            "C-04: the endpoint now answers differently for an address that exists versus "
            "one that does not, which is an account-existence oracle."
        )

    def test_the_catch_site_explains_why_it_exists(self):
        """A test that fails is necessary but not sufficient.

        Someone deleting the except would see a failure with no indication of what it was
        protecting. The comment at the call site is what makes the constraint legible at
        the point of edit - the same reasoning as the single-process notes on each
        consumer.
        """
        import inspect

        from app.api import users

        source = inspect.getsource(users.forgot_password)
        assert "C-04" in source, (
            "the catch site no longer names the finding it protects, so the next reader "
            "cannot tell the swallow from ordinary error handling"
        )
        assert "oracle" in source.lower()

    def test_login_and_registration_do_NOT_swallow_it(self):
        """The other half of the asymmetry. Both must keep surfacing 503.

        If these started swallowing too, a user whose mail failed would be told their
        login succeeded and then never receive a code.
        """
        import inspect

        from app.api import users

        for name in ("login", "register"):
            fn = getattr(users, name, None)
            if fn is None:
                continue
            source = inspect.getsource(fn)
            assert "except HTTPException" not in source, (
                f"{name} swallows the delivery-failure 503; only password reset may."
            )
