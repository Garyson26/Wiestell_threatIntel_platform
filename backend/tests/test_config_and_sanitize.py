"""Startup configuration guarantees and secret redaction."""

import pytest

from app.config import Settings
from app.utils.sanitize import REDACTED, redact_headers, redact_secrets

BASE = {"DATABASE_URL": "mysql+pymysql://u:p@h/d"}


class TestSecretKeyValidation:
    @pytest.mark.parametrize("key", ["", "change-me-in-production", "changeme", "short", "x" * 31])
    def test_production_refuses_weak_secret_key(self, key):
        with pytest.raises(ValueError, match="SECRET_KEY"):
            Settings(**BASE, SECRET_KEY=key, ENVIRONMENT="production")

    def test_staging_is_treated_as_production(self):
        with pytest.raises(ValueError, match="SECRET_KEY"):
            Settings(**BASE, SECRET_KEY="", ENVIRONMENT="staging")

    def test_production_accepts_a_strong_key(self):
        settings = Settings(**BASE, SECRET_KEY="x" * 32, ENVIRONMENT="production")
        assert settings.SECRET_KEY == "x" * 32

    def test_development_generates_an_ephemeral_key(self):
        a = Settings(**BASE, SECRET_KEY="", ENVIRONMENT="development")
        b = Settings(**BASE, SECRET_KEY="", ENVIRONMENT="development")
        assert len(a.SECRET_KEY) >= 32
        # Ephemeral: no shared default secret exists between processes.
        assert a.SECRET_KEY != b.SECRET_KEY


class TestDatabaseUrl:
    def test_database_url_is_required(self, monkeypatch, tmp_path):
        """There must be no hardcoded production DSN fallback.

        The variable is removed from the environment and the .env file is
        pointed at an empty path, otherwise pydantic-settings would satisfy the
        field from the test harness's own configuration.
        """
        monkeypatch.delenv("DATABASE_URL", raising=False)
        empty_env = tmp_path / "empty.env"
        empty_env.write_text("")

        with pytest.raises(Exception, match="DATABASE_URL"):
            Settings(SECRET_KEY="x" * 32, ENVIRONMENT="production", _env_file=str(empty_env))

    def test_async_url_is_derived_when_absent(self):
        settings = Settings(**BASE, SECRET_KEY="x" * 32)
        assert settings.DATABASE_ASYNC_URL.startswith("mysql+aiomysql://")


class TestCorsAndDocs:
    def test_wildcard_origin_is_dropped(self):
        settings = Settings(
            **BASE, SECRET_KEY="x" * 32, ENVIRONMENT="production",
            CORS_ORIGINS="*,https://wiestell.com",
        )
        assert settings.cors_origin_list == ["https://wiestell.com"]

    def test_bare_wildcard_yields_no_origins(self):
        settings = Settings(**BASE, SECRET_KEY="x" * 32, CORS_ORIGINS="*")
        assert settings.cors_origin_list == []

    def test_docs_closed_in_production_open_in_development(self):
        prod = Settings(**BASE, SECRET_KEY="x" * 32, ENVIRONMENT="production")
        dev = Settings(**BASE, SECRET_KEY="x" * 32, ENVIRONMENT="development")
        assert prod.docs_enabled is False
        assert dev.docs_enabled is True

    def test_docs_can_be_explicitly_enabled(self):
        settings = Settings(
            **BASE, SECRET_KEY="x" * 32, ENVIRONMENT="production", ENABLE_API_DOCS=True
        )
        assert settings.docs_enabled is True


class TestFeedApiKeyAllowlist:
    def test_sensitive_names_are_not_allowlisted(self):
        from app.config import ALLOWED_FEED_API_KEY_ENVS

        for name in ("SECRET_KEY", "DATABASE_URL", "RESEND_API_KEY", "CRON_SECRET", "PATH"):
            assert name not in ALLOWED_FEED_API_KEY_ENVS


class TestRedaction:
    def test_connection_string_password_is_masked(self):
        text = (
            "OperationalError: (2003) Can't connect to "
            "mysql+aiomysql://dbuser:S3cr3tPw@10.0.0.5/tip"
        )
        out = redact_secrets(text)
        assert "S3cr3tPw" not in out
        assert "dbuser" in out          # identity kept, credential removed
        assert REDACTED in out

    def test_any_scheme_is_covered(self):
        assert "hunter2" not in redact_secrets("redis://user:hunter2@cache:6379/0")
        assert "pw" not in redact_secrets("https://admin:pw@example.com/path")

    def test_configured_secret_values_are_masked(self, monkeypatch):
        from app.config import settings

        monkeypatch.setattr(settings, "GROQ_API_KEY", "gsk_live_abcdefghijklmnop")
        assert "gsk_live_abcdefghijklmnop" not in redact_secrets(
            "Groq rejected key gsk_live_abcdefghijklmnop"
        )

    def test_short_values_are_not_masked(self, monkeypatch):
        """Masking a 2-char secret would mangle unrelated text."""
        from app.config import settings

        monkeypatch.setattr(settings, "GROQ_API_KEY", "ab")
        assert redact_secrets("a stable table") == "a stable table"

    def test_none_and_exceptions_are_handled(self):
        assert redact_secrets(None) == ""
        assert "boom" in redact_secrets(RuntimeError("boom"))

    def test_credential_headers_are_masked(self):
        out = redact_headers({
            "Authorization": "Bearer eyJhbGciOi.payload.sig",
            "Cookie": "session=abc",
            "X-Cron-Secret": "cron-value",
            "X-Api-Key": "key-value",
            "User-Agent": "curl/8.0",
            "Content-Type": "application/json",
        })
        assert out["Authorization"] == REDACTED
        assert out["Cookie"] == REDACTED
        assert out["X-Cron-Secret"] == REDACTED
        assert out["X-Api-Key"] == REDACTED
        # Non-sensitive headers survive for debugging value.
        assert out["User-Agent"] == "curl/8.0"
        assert out["Content-Type"] == "application/json"

    def test_header_matching_is_case_insensitive(self):
        out = redact_headers({"AUTHORIZATION": "Bearer x", "cookie": "a=b"})
        assert out["AUTHORIZATION"] == REDACTED
        assert out["cookie"] == REDACTED


class TestFeedResponseRedaction:
    def test_last_sync_error_is_scrubbed_on_serialisation(self):
        from datetime import datetime

        from app.schemas.feed import FeedResponse

        response = FeedResponse(
            id="feed-1", slug="urlhaus", name="URLhaus", feed_type="csv",
            api_key_env=None, is_enabled=True, last_sync_at=datetime(2026, 1, 1),
            last_sync_status="failed",
            last_sync_error="OperationalError mysql+pymysql://u:leaked@h/d timed out",
        )
        assert "leaked" not in response.last_sync_error
