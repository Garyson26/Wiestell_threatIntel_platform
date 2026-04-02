"""Abstract base class for all feed connectors."""

import abc
from typing import List, Dict, Any, Optional
from datetime import datetime, timezone

import httpx
import structlog
from tenacity import retry, stop_after_attempt, wait_exponential, retry_if_exception

logger = structlog.get_logger()


def _is_retryable(exc: BaseException) -> bool:
    """Return True only for transient failures worth retrying.

    Non-transient HTTP errors (401, 402, 403, 422, …) should not be retried —
    they will never succeed without a config change and burning retries just
    delays the failure and wastes API quota.
    Retryable: network/timeout errors, 429 Too Many Requests, 5xx server errors.
    """
    if isinstance(exc, httpx.HTTPStatusError):
        return exc.response.status_code in (429, 500, 502, 503, 504)
    # Retry on connection-level errors (timeout, DNS, SSL, etc.)
    return isinstance(exc, (httpx.TimeoutException, httpx.ConnectError, httpx.RemoteProtocolError))


class BaseFeed(abc.ABC):
    """Abstract base class for threat intelligence feed connectors."""

    name: str = "Unknown Feed"
    slug: str = "unknown"
    feed_type: str = "api"
    url: str = ""
    description: str = ""
    requires_api_key: bool = False
    api_key_env: Optional[str] = None
    default_sync_frequency: int = 3600

    def __init__(self, api_key: Optional[str] = None):
        self.api_key = api_key
        self._client = None

    @property
    def client(self) -> httpx.AsyncClient:
        if self._client is None:
            self._client = httpx.AsyncClient(
                timeout=30.0,
                follow_redirects=True,
                headers={"User-Agent": "SENTINEL-TIP/1.0"},
            )
        return self._client

    @abc.abstractmethod
    async def fetch(self) -> Any:
        """Fetch raw data from the feed source."""
        ...

    @abc.abstractmethod
    async def parse(self, raw_data: Any) -> List[Dict[str, Any]]:
        """Parse raw data into normalized IOC dicts."""
        ...

    async def run(self) -> List[Dict[str, Any]]:
        """Execute the full feed pipeline: fetch -> parse.

        Exceptions from fetch() or parse() are intentionally NOT caught here so
        that they propagate to run_feed_sync, which records them as
        last_sync_status='failed' / last_sync_error in the database.  Swallowing
        exceptions here would produce a misleading 'no_data' status instead.
        """
        try:
            logger.info("feed_fetch_start", feed=self.name)
            raw_data = await self.fetch()
            iocs = await self.parse(raw_data)
            logger.info("feed_fetch_complete", feed=self.name, ioc_count=len(iocs))
            return iocs
        finally:
            if self._client:
                await self._client.aclose()
                self._client = None

    @retry(
        stop=stop_after_attempt(3),
        wait=wait_exponential(multiplier=1, min=2, max=30),
        retry=retry_if_exception(_is_retryable),
        reraise=True,
    )
    async def _fetch_url(self, url: str, **kwargs) -> httpx.Response:
        """Fetch URL with retry logic (retries only on transient errors)."""
        response = await self.client.get(url, **kwargs)
        response.raise_for_status()
        return response

    def _make_ioc(
        self,
        ioc_type: str,
        value: str,
        tags: Optional[List[str]] = None,
        threat_score: Optional[int] = None,
        confidence: int = 50,
        metadata: Optional[Dict] = None,
        mitre_techniques: Optional[List[str]] = None,
        first_seen: Optional[datetime] = None,
        last_seen: Optional[datetime] = None,
    ) -> Dict[str, Any]:
        """Create a standardized IOC dict."""
        return {
            "type": ioc_type,
            "value": value.strip(),
            "tags": tags or [],
            "threat_score": threat_score,
            "confidence": confidence,
            "metadata": metadata or {},
            "mitre_techniques": mitre_techniques or [],
            "first_seen": first_seen or datetime.now(timezone.utc),
            "last_seen": last_seen or datetime.now(timezone.utc),
            "raw_data": None,
        }
