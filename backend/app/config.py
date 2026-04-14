"""Application configuration loaded from environment variables."""

from pathlib import Path
from pydantic_settings import BaseSettings
from typing import Optional


class Settings(BaseSettings):
    """Application settings loaded from environment variables."""

    # Database
    DATABASE_URL: str = "mysql+pymysql://u433859718_wiest_tell:C9b%3E%3BxrFy@193.203.184.197/u433859718_intel_wies_tel"
    DATABASE_ASYNC_URL: str = "mysql+aiomysql://u433859718_wiest_tell:C9b%3E%3BxrFy@193.203.184.197/u433859718_intel_wies_tel"

    # Redis (Optional - not available on Vercel serverless)
    REDIS_URL: Optional[str] = None

    # API Keys (all optional)
    OTX_API_KEY: Optional[str] = None
    ABUSEIPDB_API_KEY: Optional[str] = None
    VT_API_KEY: Optional[str] = None
    SHODAN_API_KEY: Optional[str] = None
    PHISHTANK_API_KEY: Optional[str] = None
    MALWAREBAZAAR_API_KEY: Optional[str] = None
    THREATFOX_API_KEY: Optional[str] = None
    URLHAUS_API_KEY: Optional[str] = None

    # AI
    GROQ_API_KEY: str = ""

    # App Config
    SECRET_KEY: str = "change-me-in-production"
    ENVIRONMENT: str = "development"
    LOG_LEVEL: str = "INFO"
    FEED_SYNC_INTERVAL: int = 3600
    PORT: int = 8000
    CORS_ORIGINS: str = "https://wiestell.com,https://www.wiestell.com"

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

    # Email Configuration
    EMAIL_SERVICE: str = "smtp"
    EMAIL_USER: str = "noreply@wiestell.com"
    EMAIL_PASSWORD: str = "q9#pcv5aC~"
    SMTP_HOST: str = "smtp.hostinger.com"
    SMTP_PORT: int = 465
    SMTP_SECURE: bool = True
    ADMIN_EMAIL: str = "viraj.470@gmail.com"  # Email for error notifications
    ENABLE_ERROR_EMAILS: bool = True  # Toggle error email notifications

    class Config:
        # Find .env file relative to this config.py file (backend/app/.env -> ../../.env)
        env_file = str(Path(__file__).parent.parent / ".env")
        case_sensitive = True
        extra = 'ignore'  # Ignore extra environment variables not in Settings

    def model_post_init(self, __context) -> None:
        if not self.DATABASE_ASYNC_URL:
            self.DATABASE_ASYNC_URL = self.DATABASE_URL.replace(
                "mysql+pymysql://", "mysql+aiomysql://"
            )


settings = Settings()
