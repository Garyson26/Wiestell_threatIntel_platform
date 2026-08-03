"""Abstract base class for all feed connectors."""

import abc
from typing import Any, Dict, List, Optional, Tuple
from datetime import datetime, timezone

import httpx
import structlog
from tenacity import retry, stop_after_attempt, wait_exponential, retry_if_exception

logger = structlog.get_logger()

# ── Full-list export kinds — see BaseFeed.full_list_kind ─────────────────────
# A list that expires entries: presence re-asserts liveness.
FULL_LIST_CURRENT_STATE = "current-state"
# A list that only grows: presence says nothing about today.
FULL_LIST_CUMULATIVE = "cumulative"
FULL_LIST_KINDS = frozenset({FULL_LIST_CURRENT_STATE, FULL_LIST_CUMULATIVE})


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

    # ── Rolling-window exports ───────────────────────────────────────────────
    # Set True by a connector whose source is a *rolling window* rather than a
    # full catalogue — a file holding "the last N hours" of records, where an
    # interval longer than the window means records fall through the gap unseen
    # and unlogged. MalwareBazaar's public export is the case that prompted this:
    # 881 samples over a measured 47.78 hours, and the file appears entry-capped
    # rather than time-bounded, so a campaign spike shrinks the window without
    # anything changing on our side.
    #
    # A connector that opts in must populate `observed_window` during parse().
    # `run_feed_sync` then compares the new file's earliest record against the
    # previous sync's latest and records a gap on the feed row.
    #
    # Opt-in rather than derived from the parsed IOCs on purpose: `_make_ioc`
    # defaults an absent first_seen to now(), so a feed whose source carries no
    # timestamps (blocklist.de, emergingthreats) would report a gap on *every*
    # sync. Only a connector that actually read timestamps out of a file can say
    # what the window was.
    rolling_window: bool = False

    # ── Full-list exports ────────────────────────────────────────────────────
    # Set by a connector whose source publishes its ENTIRE current list every time,
    # with no per-record timestamps: blocklist.de's all.txt, Emerging Threats'
    # compromised-ips, the CISA KEV catalogue, eCrimeLabs' CVE list, MISP CERT-FR's
    # hash file. Measured 2026-07-31: 30,826 records between them, 59.9% of all
    # records ingested per sync.
    #
    # Why it must be declared rather than detected: `_make_ioc` defaults an absent
    # first_seen/last_seen to now(), so downstream these look identical to a feed
    # reporting a genuinely fresh observation. The re-read gate could not fire for any
    # of them and `sighting_count` incremented on every sync — saturating
    # `_sighting_frequency_score` at its 100.0 ceiling within about a day and pinning
    # 15% of the composite at maximum across most of the corpus.
    #
    # A connector knows what its own feed is even when the records do not say.
    #
    # TWO KINDS, and the distinction changes behaviour:
    #
    #   FULL_LIST_CURRENT_STATE — the list EXPIRES entries. Remaining on it is the
    #       source genuinely re-asserting that the indicator is live, which is real
    #       recency information and the only signal these feeds carry. So `last_seen`
    #       advances; the counter does not, because presence is not an observation
    #       *event*. blocklist.de and Emerging Threats.
    #
    #   FULL_LIST_CUMULATIVE — the list only GROWS. An entry is added and stays
    #       forever, so its presence today says nothing about today.
    #       CVE-2021-44228 appearing in the KEV export is not evidence it was
    #       observed today, only that the catalogue still contains it. Both
    #       `last_seen` and the counter freeze.
    #
    #       Advancing `last_seen` for a cumulative feed would pin `_recency_score` at
    #       100.0 permanently and destroy the decay: the measured KEV trajectory
    #       (d0=83 ... d365=74) only decays because that fixture holds `last_seen`
    #       fixed. In the live corpus every KEV CVE would sit at its day-0 score
    #       forever, undoing the monotone-non-increasing property. It would also be
    #       the third count of one signal — KEV membership is already carried by
    #       `_enrichment_risk_score`'s `nvd_in_kev` branch and by the `cisa-kev`
    #       context tag.
    #
    #       Verified rather than assumed for MISP CERT-FR: its MISP manifest holds 18
    #       events spanning 2020-2024 and the hashes CSV carries no date column, so
    #       it is cumulative. Incident-response hashes do not stop being bad.
    full_list_kind: Optional[str] = None

    def __init__(self, api_key: Optional[str] = None):
        self.api_key = api_key
        self._client = None
        # (earliest, latest) record timestamps seen in this run, or None.
        self.observed_window: Optional[Tuple[datetime, datetime]] = None

    def record_observed_window(self, timestamps: List[Optional[datetime]]) -> None:
        """Record the min/max of the timestamps a rolling-window parse saw.

        Tolerates Nones and an empty list — a feed that returned nothing simply
        leaves ``observed_window`` as None, which the continuity check reads as
        "no evidence either way" rather than as a gap.
        """
        real = [ts for ts in timestamps if ts is not None]
        self.observed_window = (min(real), max(real)) if real else None

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
            # Did the SOURCE report a timestamp, or did we default to now()?
            #
            # This has to be recorded here because it is unrecoverable afterwards:
            # the two lines above make "the source said 2026-07-28" and "the source
            # said nothing" indistinguishable downstream. feed_ingestion's re-read
            # gate needs the difference — a feed with no timestamps (blocklist.de,
            # Emerging Threats) must keep its current always-rescore behaviour,
            # because for it every sync genuinely looks like a fresh observation.
            #
            # Leading underscore marks it as ingestion metadata rather than an IOC
            # field; the INSERT builds its column list explicitly, so it is never
            # written to the database.
            "_source_timestamped": bool(first_seen or last_seen),
            # None, "current-state" or "cumulative" — see BaseFeed.full_list_kind.
            "_full_list_kind": self.full_list_kind,
            "raw_data": None,
        }
