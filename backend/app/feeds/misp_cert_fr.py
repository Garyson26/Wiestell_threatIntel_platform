"""
MISP CERT-FR feed connector.

Fetches MD5 hashes from French ANSSI (CERT-FR) government incident response
cases published via MISP. Each hash is paired with a MISP event UUID that
groups related IOCs from the same investigation.

Source: https://misp.cert.ssi.gouv.fr/feed-misp/hashes.csv
"""

import csv
import logging
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

from app.feeds.base import BaseFeed, SHAPE_CUMULATIVE_CATALOGUE

logger = logging.getLogger(__name__)

_FEED_URL = "https://misp.cert.ssi.gouv.fr/feed-misp/hashes.csv"

# The MISP feed manifest: {event_uuid: {"date": "2021-03-04", "info": ...}, ...}.
# The hashes CSV's second column IS this UUID, so the two are joinable and an event
# date is a far better first_seen for an incident-response hash than the date we
# happened to sync. Measured 2026-07-31: 18 events spanning 2020-2024.
_MANIFEST_URL = "https://misp.cert.ssi.gouv.fr/feed-misp/manifest.json"

_TAGS = ["misp", "cert-fr", "anssi", "government-ir"]


def _parse_event_date(value: Any) -> Optional[datetime]:
    """A MISP manifest ``date``, which is ``YYYY-MM-DD``.

    None on anything unparseable. See the no-verdict note in ``_event_dates``.
    """
    if not isinstance(value, str) or not value.strip():
        return None
    try:
        return datetime.strptime(value.strip(), "%Y-%m-%d")
    except ValueError:
        return None


class MISPCertFRFeed(BaseFeed):
    """Feed connector for MISP CERT-FR (French government IR hashes)."""

    name = "MISP CERT-FR"
    slug = "misp-cert-fr"
    feed_type = "csv"
    url = _FEED_URL
    description = (
        "MD5 hashes from French ANSSI/CERT-FR government incident response cases"
    )
    requires_api_key = False
    # Whole list republished every sync, no per-record timestamps.
    # 2,277 MD5 hashes measured 2026-07-31. Verified cumulative: the MISP manifest
    # holds 18 events spanning 2020-2024 and the CSV has no date column.
    # See BaseFeed.full_list_kind for what each kind does.
    source_shape = SHAPE_CUMULATIVE_CATALOGUE
    default_sync_frequency = 21600  # 6 hours

    async def _event_dates(self) -> Dict[str, datetime]:
        """``{event_uuid: event_date}`` from the MISP manifest, fetched ONCE per sync.

        CACHED FOR THE RUN, deliberately. The join is one extra HTTP request and a dict
        build for ~2,277 hashes across ~18 events, so doing it per row would be 2,277
        requests to answer 18 questions. This connector runs on a 6-hour cadence and the
        manifest changes when a new IR case is published — rebuilding it per sync is
        already generous.

        MISSING OR MALFORMED MANIFEST IS A NO-VERDICT, NOT A FALLBACK.
        On any failure this returns ``{}`` and every hash gets ``first_seen=None``, which
        `_make_ioc` records as ``_source_timestamped=False``. That is the honest state:
        we do not know when the event happened. Because this feed is a
        CUMULATIVE_CATALOGUE, an existing row then keeps its stored `last_seen` and the
        counter stays frozen — the behaviour that was already correct before the join
        existed.

        What it must NOT do is substitute ``now()`` as though it were the event date.
        That would set `_source_timestamped=True`, engage the timestamped path, and make
        an unknown date look like a fresh observation — absence of evidence read as
        evidence, which is the single most repeated defect class in this codebase.
        """
        try:
            response = await self._fetch_url(_MANIFEST_URL)
            manifest = response.json()
        except Exception as exc:  # noqa: BLE001 — any failure is the same no-verdict
            logger.warning(
                "%s: manifest unavailable (%s: %s); hashes will carry no source date",
                self.name, type(exc).__name__, str(exc)[:120],
            )
            return {}

        if not isinstance(manifest, dict):
            logger.warning(
                "%s: manifest is %s, expected an object keyed by event uuid; "
                "hashes will carry no source date",
                self.name, type(manifest).__name__,
            )
            return {}

        dates: Dict[str, datetime] = {}
        for uuid, event in manifest.items():
            if not isinstance(event, dict):
                continue
            parsed = _parse_event_date(event.get("date"))
            if parsed is not None:
                dates[str(uuid).strip()] = parsed

        logger.info(
            "%s: manifest resolved %d event date(s) from %d entries",
            self.name, len(dates), len(manifest),
        )
        return dates

    async def fetch(self) -> Dict[str, Any]:
        """GET the CERT-FR hashes CSV, plus the manifest that dates its events.

        Returns both so `parse()` stays pure — it receives everything it needs rather
        than issuing its own requests, which keeps it directly testable with a fixture.
        """
        response = await self._fetch_url(_FEED_URL)
        return {"csv": response.text, "event_dates": await self._event_dates()}

    async def parse(self, raw: Any) -> List[Dict[str, Any]]:
        """Parse CSV of md5_hash,misp_event_uuid into normalised IOC dicts.

        Accepts either the ``{"csv": ..., "event_dates": ...}`` mapping that `fetch()`
        now returns, or a bare CSV string. The string form is kept because several tests
        and any manual invocation pass one, and because a signature that silently
        required the mapping would turn "called the old way" into an unhandled
        AttributeError mid-sync.
        """
        if isinstance(raw, dict):
            csv_text = raw.get("csv") or ""
            event_dates: Dict[str, datetime] = raw.get("event_dates") or {}
        else:
            csv_text = raw or ""
            event_dates = {}

        seen: set[str] = set()
        iocs: List[Dict[str, Any]] = []
        dated = 0

        lines = [
            line for line in csv_text.splitlines()
            if line.strip() and not line.strip().startswith("#")
        ]
        if not lines:
            return []

        reader = csv.reader(lines)
        for row in reader:
            if len(row) < 2:
                continue

            md5_hash = row[0].strip().lower()
            event_uuid = row[1].strip()

            if not md5_hash:
                continue

            dedup_key = f"hash:{md5_hash}"
            if dedup_key in seen:
                continue
            seen.add(dedup_key)

            # A UUID absent from the manifest is a no-verdict, exactly like an
            # unreachable manifest: None here, never now(). See `_event_dates`.
            event_date = event_dates.get(event_uuid)
            if event_date is not None:
                dated += 1

            metadata: Dict[str, Any] = {
                "source": "misp-cert-fr",
                "misp_event_uuid": event_uuid,
                "hash_type": "md5",
            }
            if event_date is not None:
                metadata["misp_event_date"] = event_date.strftime("%Y-%m-%d")

            iocs.append(self._make_ioc(
                ioc_type="hash",
                value=md5_hash,
                confidence=85,
                tags=list(_TAGS),
                metadata=metadata,
                first_seen=event_date,
                last_seen=event_date,
            ))

        logger.info(
            "%s: parsed %d hash(es), %d with a source event date (%d without)",
            self.name, len(iocs), dated, len(iocs) - dated,
        )
        return iocs
