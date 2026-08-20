"""
CISA KEV feed connector.

Fetches the Known Exploited Vulnerabilities catalogue, trying CISA's canonical URL
first and falling back to the GitHub mirror. This module previously used the mirror
ONLY, on the stated grounds that "direct CISA URLs return 403 from Cloudflare" —
measured 2026-08-17, that no longer reproduces and the comparison has inverted (CISA
200, mirror 429). See the note beside `_CANONICAL_URL`.

Sources: https://www.cisa.gov/known-exploited-vulnerabilities-catalog
         https://github.com/cisagov/kev-data (mirror)
License: CC0 (public domain)
"""

import logging
from datetime import datetime
from typing import Any, Dict, List, Optional

from app.feeds.base import BaseFeed, FeedNotModified, SHAPE_CUMULATIVE_CATALOGUE

logger = logging.getLogger(__name__)


def _describe_failure(label: str, url: str, exc: BaseException) -> str:
    """A failure description that names WHAT went wrong, not merely that it did.

    `last_sync_error` is the primary diagnostic for every feed and is served to the admin
    UI, so "it failed" forces a live probe every time. The three facts that distinguish
    the realistic causes:

      * the STATUS CODE for an HTTP error -- 403 (blocked), 429 (rate-limited) and 503
        (upstream down) call for completely different responses, and a status code is not
        a secret;
      * the EXCEPTION CLASS for a transport error, because those stringify to the EMPTY
        STRING. Measured: `str(httpx.ConnectTimeout(""))` is `''`, likewise ReadTimeout,
        ConnectError and RemoteProtocolError. A message built only from `str(exc)` is
        therefore blank for exactly the failures hardest to guess at;
      * WHICH URL was tried, since this connector has two and they fail independently.
    """
    import httpx

    detail = str(exc).strip()
    if isinstance(exc, httpx.HTTPStatusError):
        code = exc.response.status_code
        return f"{label} {url} -> HTTP {code} ({exc.response.reason_phrase})"
    if isinstance(exc, httpx.HTTPError):
        # Transport failure: the class IS the diagnosis, because str() is empty.
        return f"{label} {url} -> {type(exc).__name__}" + (f": {detail[:120]}" if detail else "")
    return f"{label} {url} -> {type(exc).__name__}" + (f": {detail[:120]}" if detail else "")


def _parse_kev_date(value: Optional[str]) -> Optional[datetime]:
    """CISA's ``dateAdded`` / ``dueDate``, which are plain ``YYYY-MM-DD``.

    Returns None on anything unparseable rather than guessing. A None flows into
    ``_make_ioc``, which defaults to ``now()`` — the pre-2026-08-17 behaviour — so a
    format change degrades to what we had rather than to a crash or a wrong date.
    Timezone-naive UTC to match the column convention; a date has no time-of-day, so
    midnight UTC is the only honest reading of it.
    """
    if not value:
        return None
    try:
        return datetime.strptime(value.strip(), "%Y-%m-%d")
    except (ValueError, AttributeError):
        logger.warning("cisa_kev_unparseable_date value=%r", value)
        return None

# CANONICAL FIRST, MIRROR AS FALLBACK — changed 2026-08-17.
#
# This module used to fetch the GitHub mirror only, justified by "direct CISA URLs return
# 403 from Cloudflare". Measured on 2026-08-17 that no longer reproduces, and the
# comparison inverted: CISA's own URL returned 200 with the full 1.58 MB catalogue, while
# the mirror returned 429 Too Many Requests.
#
# A comment justifying a workaround that does not reproduce is worse than no comment — it
# tells the next reader the canonical source is unusable when it is not. But one
# observation is not a pattern, so neither source is trusted alone: try canonical, fall
# back to the mirror on ANY non-200 or transport error, and log which one served. That is
# strictly better than either alone and it self-documents, so if CISA's Cloudflare rule
# returns it shows up as a logged fallback rather than a silent 403.
#
# PHASE 6 RE-CHECK: this was measured from a Mumbai workstation. Cloudflare's verdict is
# a function of the requesting IP, so Render's egress may well be judged differently.
# Re-run the comparison after deploy rather than assuming this result transfers.
_CANONICAL_URL = (
    "https://www.cisa.gov/sites/default/files/feeds/"
    "known_exploited_vulnerabilities.json"
)
_MIRROR_URL = (
    "https://raw.githubusercontent.com/cisagov/kev-data/"
    "develop/known_exploited_vulnerabilities.json"
)
# The class-level `url` stays the canonical one: it is what `seed_feeds.py` records and
# what an operator reads in the feeds UI, and it is now the source actually tried first.
_CATALOG_URL = _CANONICAL_URL


class CISAKEVFeed(BaseFeed):
    """Feed connector for CISA Known Exploited Vulnerabilities."""

    name = "CISA KEV"
    slug = "cisa-kev"
    feed_type = "api"
    url = _CATALOG_URL
    description = (
        "CISA Known Exploited Vulnerabilities — CVEs with confirmed "
        "in-the-wild exploitation"
    )
    requires_api_key = False
    # Whole list republished every sync, no per-record timestamps.
    # 1,656 CVEs measured 2026-07-31. The KEV catalogue only grows; a CVE added in
    # 2021 is still listed, so presence today is not an observation today.
    # See BaseFeed.full_list_kind for what each kind does.
    source_shape = SHAPE_CUMULATIVE_CATALOGUE
    default_sync_frequency = 86400  # catalogue updates at most daily

    async def fetch(self) -> Dict[str, Any]:
        """GET the KEV catalogue: CISA canonical first, GitHub mirror on failure.

        Logs which source served so the working path is visible in production rather than
        inferred. See the note beside `_CANONICAL_URL` for why neither is trusted alone.
        """
        errors: List[str] = []
        for label, url in (("canonical", _CANONICAL_URL), ("mirror", _MIRROR_URL)):
            try:
                response = await self._fetch_url(url)
                payload = response.json()
            except FeedNotModified:
                # NOT a source failure -- must propagate so run() can short-circuit.
                # Swallowing it here is the bug that took this feed to
                # consecutive_failures = 6: the 304 was read as "canonical failed", the
                # mirror was tried, it also 304'd, and the feed was recorded as FAILED
                # while both sources were answering correctly.
                raise
            except Exception as exc:  # noqa: BLE001 — any other failure falls through
                errors.append(_describe_failure(label, url, exc))
                logger.warning("cisa_kev_source_failed source=%s error=%s",
                               label, errors[-1])
                continue

            count = len((payload or {}).get("vulnerabilities") or [])
            if not count:
                # A 200 carrying no entries is a failure for our purposes: ingesting it
                # would look like a successful sync of an empty catalogue. Fall through
                # rather than accepting it.
                errors.append(f"{label} {url} -> HTTP 200 but 0 vulnerabilities")
                logger.warning("cisa_kev_source_empty source=%s", label)
                continue

            logger.info("cisa_kev_source_served source=%s entries=%d", label, count)
            return payload

        raise RuntimeError(
            "CISA KEV unavailable from both sources: " + "; ".join(errors)
        )

    async def parse(self, raw: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Parse the KEV catalog into normalised CVE IOC dicts."""
        seen: set[str] = set()
        iocs: List[Dict[str, Any]] = []

        for entry in raw.get("vulnerabilities") or []:
            ioc = self._parse_entry(entry, seen)
            if ioc is not None:
                iocs.append(ioc)

        logger.info("%s: parsed %d CVE(s)", self.name, len(iocs))
        return iocs

    def _parse_entry(
        self, entry: Dict[str, Any], seen: set[str],
    ) -> Optional[Dict[str, Any]]:
        """Convert a single KEV entry to a CVE IOC dict, or None."""
        cve_id = (entry.get("cveID") or "").strip()
        if not cve_id:
            return None

        dedup_key = f"cve:{cve_id}"
        if dedup_key in seen:
            return None
        seen.add(dedup_key)

        vendor = (entry.get("vendorProject") or "").strip()
        ransomware_use = (entry.get("knownRansomwareCampaignUse") or "").strip()

        tags: list[str] = ["cisa-kev"]
        if vendor:
            tags.append(vendor.lower())
        if ransomware_use == "Known":
            tags.append("ransomware")

        metadata: dict[str, Any] = {
            "vendor":             vendor,
            "product":            (entry.get("product") or "").strip(),
            "vulnerability_name": (entry.get("vulnerabilityName") or "").strip(),
            "date_added":         (entry.get("dateAdded") or "").strip(),
            "due_date":           (entry.get("dueDate") or "").strip(),
            "required_action":    (entry.get("requiredAction") or "").strip(),
            "ransomware_use":     ransomware_use,
            "cwes":               entry.get("cwes") or [],
            "source":             "cisa-kev",
        }

        # `dateAdded` was parsed into metadata and then dropped on the floor. Because
        # `_make_ioc` defaults an absent stamp to now(), `last_seen` recorded the date WE
        # ingested the entry rather than the date CISA added it — for a catalogue going
        # back to 2021, potentially years off. Fixed 2026-08-17 (Phase 4 Section C).
        #
        # This does NOT unfreeze the counter. `dateAdded` never moves for an existing
        # entry, so the re-read gate still never fires and CUMULATIVE_CATALOGUE still
        # freezes both stamps. What changes is that recency is now ACCURATE: a KEV CVE
        # added last week reads fresh and a 2021 entry decays correctly, instead of every
        # entry looking as though it were first seen on the day we happened to sync.
        #
        # That is the difference between "frozen because we have no information" and
        # "frozen because the source says nothing changed".
        added = _parse_kev_date(entry.get("dateAdded"))

        return self._make_ioc(
            ioc_type="cve",
            value=cve_id,
            confidence=95,
            tags=tags,
            metadata=metadata,
            first_seen=added,
            last_seen=added,
        )
