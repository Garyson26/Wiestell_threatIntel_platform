"""Application configuration loaded from environment variables.

Security note: this module must never contain real credentials. Every secret is
sourced from the environment (or the local ``.env`` file, which is git-ignored).
Missing or insecure secrets fail fast in production rather than silently falling
back to a shared default.
"""

import secrets
from pathlib import Path
from typing import List, Optional

from pydantic import Field, field_validator
from pydantic_settings import BaseSettings

# Placeholder values that must never be used outside local development.
INSECURE_SECRET_KEYS = {
    "",
    "change-me-in-production",
    "changeme",
    "secret",
    "development",
}

# Environment variable names a feed row is allowed to reference for its API key.
# Without this allowlist an operator (or an attacker who reached the feed API)
# could point ``feed.api_key_env`` at SECRET_KEY / DATABASE_URL / EMAIL_PASSWORD
# and have the value forwarded to a third-party feed endpoint.
#
# Kept to exactly the names a live feed connector declares — audited 2026-07-29,
# 11 entries down to 5. Two axes of removal:
#
#   * VT_API_KEY / PHISHTANK_API_KEY — connector modules deleted.
#   * SHODAN_API_KEY / NVD_API_KEY / YARAIFY_API_KEY / CVEDETAILS_ACCESS_TOKEN —
#     enricher-only. These are read from ``settings`` directly in
#     ``enrichers/__init__.py::build_registry`` and the enricher constructors; no
#     connector class declares them, so no ``feed_sources`` row could ever cause
#     them to be dereferenced. They remain ``Settings`` fields below — only their
#     reachability from a feed row is withdrawn.
#
# Adding a name here widens the exfiltration surface, so add one only when a
# connector actually reads a key from it.
ALLOWED_FEED_API_KEY_ENVS = frozenset({
    "OTX_API_KEY",            # otx_alienvault — required
    "ABUSEIPDB_API_KEY",      # abuseipdb — required
    "THREATFOX_API_KEY",      # threatfox — optional Auth-Key
    "MALWAREBAZAAR_API_KEY",  # malwarebazaar — optional Auth-Key + export path
    "URLHAUS_API_KEY",        # urlhaus — optional export path
})


class Settings(BaseSettings):
    """Application settings loaded from environment variables."""

    # ── Database (required — no default so a missing value fails fast) ────────
    DATABASE_URL: str = Field(..., min_length=1)
    DATABASE_ASYNC_URL: str = ""

    # Redis (Optional - not available on Vercel serverless)
    REDIS_URL: Optional[str] = None

    # ── API Keys (all optional) ───────────────────────────────────────────────
    OTX_API_KEY: Optional[str] = None
    ABUSEIPDB_API_KEY: Optional[str] = None
    SHODAN_API_KEY: Optional[str] = None
    MALWAREBAZAAR_API_KEY: Optional[str] = None
    THREATFOX_API_KEY: Optional[str] = None
    URLHAUS_API_KEY: Optional[str] = None

    # Vulnerability / malware enrichment sources.
    # NVD works unauthenticated at 5 req/30s; a key raises that to 50 req/30s.
    NVD_API_KEY: Optional[str] = None
    # YARAify uses an abuse.ch Auth-Key; falls back to MALWAREBAZAAR_API_KEY.
    YARAIFY_API_KEY: Optional[str] = None
    # CVE Details requires a paid subscription; the enricher is not registered
    # without it.
    CVEDETAILS_ACCESS_TOKEN: Optional[str] = None

    # AI
    GROQ_API_KEY: str = ""

    # ── App Config ────────────────────────────────────────────────────────────
    SECRET_KEY: str = ""
    ENVIRONMENT: str = "development"
    LOG_LEVEL: str = "INFO"
    FEED_SYNC_INTERVAL: int = 3600
    PORT: int = 8000
    CORS_ORIGINS: str = "https://wiestell.com,https://www.wiestell.com"

    # Interactive API docs (/docs, /redoc, /openapi.json). Off by default so a
    # production deployment does not publish its whole attack surface.
    ENABLE_API_DOCS: bool = False

    # Shared secret required by machine-triggered maintenance endpoints
    # (feed sync-all, enrichment backfill) when called without a user token.
    CRON_SECRET: str = ""

    # ── Auth / session ────────────────────────────────────────────────────────
    JWT_ALGORITHM: str = "HS256"
    JWT_EXPIRE_MINUTES: int = 720          # 12 hours
    OTP_TTL_MINUTES: int = 5
    OTP_RESET_TTL_MINUTES: int = 10
    OTP_MAX_ATTEMPTS: int = 5
    # Per-IP limits for unauthenticated auth endpoints
    AUTH_RATE_LIMIT_MAX: int = 10
    AUTH_RATE_LIMIT_WINDOW: int = 300      # seconds

    # GeoIP
    GEOIP_DB_PATH: str = "/app/data/GeoLite2-City.mmdb"

    # Pagination
    DEFAULT_PAGE_SIZE: int = 50
    MAX_PAGE_SIZE: int = 500

    # Cache TTLs (seconds)
    CACHE_TTL_WHOIS: int = 86400      # 24 hours
    CACHE_TTL_DNS: int = 3600          # 1 hour
    CACHE_TTL_GEOIP: int = 86400       # 24 hours
    CACHE_TTL_REPUTATION: int = 21600   # 6 hours
    CACHE_TTL_DASHBOARD: int = 60       # 1 minute

    # ── Email Configuration (credentials come from the environment only) ──────
    EMAIL_SERVICE: str = "smtp"
    EMAIL_USER: str = ""
    EMAIL_PASSWORD: str = ""
    SMTP_HOST: str = ""
    SMTP_PORT: int = 465
    SMTP_SECURE: bool = True
    ADMIN_EMAIL: str = ""               # Recipient for error notifications
    ENABLE_ERROR_EMAILS: bool = False   # Opt-in: alert emails carry request context

    class Config:
        # Find .env file relative to this config.py file (backend/app/config.py -> backend/.env)
        env_file = str(Path(__file__).parent.parent / ".env")
        case_sensitive = True
        extra = "ignore"  # Ignore extra environment variables not in Settings

    # ── Derived helpers ───────────────────────────────────────────────────────

    @property
    def is_production(self) -> bool:
        return self.ENVIRONMENT.lower() in {"production", "prod", "staging"}

    @property
    def cors_origin_list(self) -> List[str]:
        """Explicit list of allowed origins. Never returns a wildcard."""
        return [o.strip() for o in self.CORS_ORIGINS.split(",") if o.strip() and o.strip() != "*"]

    @property
    def docs_enabled(self) -> bool:
        return self.ENABLE_API_DOCS or not self.is_production

    @field_validator("ENVIRONMENT")
    @classmethod
    def _normalize_environment(cls, v: str) -> str:
        return (v or "development").strip().lower()

    def model_post_init(self, __context) -> None:
        if not self.DATABASE_ASYNC_URL:
            self.DATABASE_ASYNC_URL = self.DATABASE_URL.replace(
                "mysql+pymysql://", "mysql+aiomysql://"
            )

        if self.SECRET_KEY.strip() in INSECURE_SECRET_KEYS or len(self.SECRET_KEY) < 32:
            if self.is_production:
                raise ValueError(
                    "SECRET_KEY must be set to a random value of at least 32 characters "
                    "in production. Generate one with: python -c "
                    "\"import secrets; print(secrets.token_urlsafe(48))\""
                )
            # Development: use an ephemeral key so tokens never validate across
            # restarts and no shared default secret exists in the codebase.
            self.SECRET_KEY = secrets.token_urlsafe(48)


settings = Settings()
