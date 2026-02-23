"""Application configuration loaded from environment variables."""

from pydantic_settings import BaseSettings
from typing import Optional


class Settings(BaseSettings):
    """Application settings loaded from environment variables."""

    # Database
    DATABASE_URL: str = "postgresql://sentinel:sentinel@db:5432/sentinel"
    DATABASE_ASYNC_URL: str = ""

    # Redis
    REDIS_URL: str = "redis://redis:6379/0"

    # API Keys (all optional)
    OTX_API_KEY: Optional[str] = None
    ABUSEIPDB_API_KEY: Optional[str] = None
    VT_API_KEY: Optional[str] = None
    SHODAN_API_KEY: Optional[str] = None
    PHISHTANK_API_KEY: Optional[str] = None

    # AI
    GROQ_API_KEY: str = ""

    # App Config
    SECRET_KEY: str = "change-me-in-production"
    ENVIRONMENT: str = "development"
    LOG_LEVEL: str = "INFO"
    FEED_SYNC_INTERVAL: int = 3600
    PORT: int = 8000
    CORS_ORIGINS: str = "*"

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

    class Config:
        env_file = ".env"
        case_sensitive = True

    def model_post_init(self, __context) -> None:
        if not self.DATABASE_ASYNC_URL:
            self.DATABASE_ASYNC_URL = self.DATABASE_URL.replace(
                "postgresql://", "postgresql+asyncpg://"
            )


settings = Settings()
