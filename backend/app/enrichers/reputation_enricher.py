"""Aggregate reputation enrichment across AbuseIPDB and OTX.

The payload is an *evidence* record, not just a number. ``aggregate_score`` alone
cannot distinguish the three cases the scoring engine has to tell apart:

  * a provider covering this IOC type answered and flagged the indicator
  * a provider covering this IOC type answered and had nothing on it
  * no provider covering this IOC type was configured or reachable

``sources_checked`` collapses the last two into one number, and it says nothing
about *which* providers cover the type — AbuseIPDB is IP-only, so for a URL or a
hash "one source checked" means OTX alone. So each provider also reports itself
in ``providers``; see :meth:`ReputationEnricher.enrich`.
"""

from typing import Any, Dict, List, Optional

import structlog

from app.config import settings
from app.enrichers.base import BaseEnricher

logger = structlog.get_logger()

# IOC types each provider can answer for. A provider outside this set was never
# consulted for the indicator, so its silence carries no information.
_ABUSEIPDB_TYPES = {"ip"}
_OTX_TYPES = {"ip", "domain", "url", "hash"}


def _provider_record(
    name: str,
    *,
    supports_type: bool,
    configured: bool,
    responded: bool = False,
    verdict: str = "unavailable",
    corroboration: int = 0,
) -> Dict[str, Any]:
    """One provider's contribution to the evidence record.

    ``verdict`` is one of:

    ``malicious``
        A positive detection.
    ``harmless``
        The provider answered, reported no detection, **and** backed that with a
        non-zero ``corroboration`` count (reports / samples / analyses). Only
        this shape justifies a 0.0 reputation score.
    ``silent``
        Answered, no detection, no corroboration. "Never seen it" is an absence
        of evidence, not evidence of safety.
    ``unavailable``
        Not configured, does not cover this IOC type, or the call failed.
    """
    return {
        "name": name,
        "supports_type": supports_type,
        "configured": configured,
        "responded": responded,
        "verdict": verdict,
        "corroboration": int(corroboration),
    }


class ReputationEnricher(BaseEnricher):
    """Queries every configured reputation provider and averages their verdicts.

    Providers without an API key are skipped rather than reported as clean;
    ``sources_checked == 0`` is surfaced in a ``note`` so a zero score is never
    mistaken for a confirmed-benign result.
    """

    name = "reputation"

    @property
    def cache_ttl(self) -> int:
        return settings.CACHE_TTL_REPUTATION

    def supports(self, ioc_type: str) -> bool:
        # Reputation is the universal fallback: it applies to every IOC type.
        return True

    async def enrich(self, value: str, ioc_type: str) -> Optional[Dict[str, Any]]:
        import httpx

        sources_checked = 0
        sources_flagged = 0
        details: Dict[str, Any] = {}
        providers: List[Dict[str, Any]] = []
        scores = []

        # ── AbuseIPDB (IPs only) ──────────────────────────────────────────────
        supports_abuseipdb = ioc_type in _ABUSEIPDB_TYPES
        has_abuseipdb_key = bool(settings.ABUSEIPDB_API_KEY)
        abuseipdb = _provider_record(
            "abuseipdb",
            supports_type=supports_abuseipdb,
            configured=has_abuseipdb_key,
        )
        if supports_abuseipdb and has_abuseipdb_key:
            try:
                async with httpx.AsyncClient(timeout=15) as client:
                    response = await client.get(
                        "https://api.abuseipdb.com/api/v2/check",
                        params={"ipAddress": value, "maxAgeInDays": 90},
                        headers={
                            "Key": settings.ABUSEIPDB_API_KEY,
                            "Accept": "application/json",
                        },
                    )
                    if response.status_code == 200:
                        data = response.json().get("data", {})
                        abuse_score = data.get("abuseConfidenceScore", 0)
                        total_reports = data.get("totalReports", 0) or 0
                        sources_checked += 1
                        if abuse_score > 0:
                            sources_flagged += 1
                            scores.append(abuse_score)
                        details["abuseipdb"] = {
                            "score": abuse_score,
                            "reports": total_reports,
                            "last_reported": data.get("lastReportedAt"),
                            "is_whitelisted": data.get("isWhitelisted", False),
                        }
                        # The confidence score is *derived from* abuse reports, so
                        # zero reports means nobody has assessed this address —
                        # silence. Reports that exist but produced no confidence
                        # is the one shape that is genuinely exculpatory.
                        if abuse_score > 0:
                            verdict = "malicious"
                        elif total_reports > 0:
                            verdict = "harmless"
                        else:
                            verdict = "silent"
                        abuseipdb = _provider_record(
                            "abuseipdb",
                            supports_type=True,
                            configured=True,
                            responded=True,
                            verdict=verdict,
                            corroboration=total_reports,
                        )
            except Exception as e:
                logger.warning("abuseipdb_reputation_failed", error=str(e))
        providers.append(abuseipdb)

        # ── AlienVault OTX (IPs, domains, URLs, hashes) ───────────────────────
        supports_otx = ioc_type in _OTX_TYPES
        has_otx_key = bool(settings.OTX_API_KEY)
        otx = _provider_record(
            "otx", supports_type=supports_otx, configured=has_otx_key
        )
        if supports_otx and has_otx_key:
            try:
                otx_type = {
                    "ip": "IPv4", "domain": "domain", "url": "url", "hash": "file",
                }.get(ioc_type)

                if otx_type:
                    async with httpx.AsyncClient(timeout=15) as client:
                        response = await client.get(
                            f"https://otx.alienvault.com/api/v1/indicators/"
                            f"{otx_type}/{value}/general",
                            headers={"X-OTX-API-KEY": settings.OTX_API_KEY},
                        )
                        if response.status_code == 200:
                            data = response.json()
                            pulse_count = data.get("pulse_info", {}).get("count", 0) or 0

                            sources_checked += 1
                            if pulse_count > 0:
                                sources_flagged += 1
                                scores.append(min(pulse_count * 10, 100))

                            details["otx"] = {
                                "pulse_count": pulse_count,
                                "validation": data.get("validation", []),
                                "sections": list(data.get("sections", [])),
                            }
                            # OTX has no clean-assertion channel: zero pulses means
                            # "no pulse mentions this indicator", which is exactly
                            # the expected state for an indicator nobody has
                            # written up yet. It can never be `harmless`.
                            otx = _provider_record(
                                "otx",
                                supports_type=True,
                                configured=True,
                                responded=True,
                                verdict="malicious" if pulse_count > 0 else "silent",
                                corroboration=pulse_count,
                            )
            except Exception as e:
                logger.warning("otx_reputation_failed", error=str(e))
        providers.append(otx)

        aggregate_score = int(sum(scores) / len(scores)) if scores else 0

        # `aggregate_score` is assessable only if a provider covering this IOC type
        # reached an actual verdict. A provider that answered but was silent has told
        # us nothing — the same absence the reputation term itself refuses to read as
        # cleanliness, so it must not enter the risk denominator either.
        reached_verdict = any(
            p["supports_type"] and p["responded"]
            and p["verdict"] in ("malicious", "harmless")
            for p in providers
        )
        result: Dict[str, Any] = {
            "aggregate_score": aggregate_score,
            "sources_checked": sources_checked,
            "sources_flagged": sources_flagged,
            "providers": providers,
            "details": details,
            "assessed": ["aggregate_score"] if reached_verdict else [],
        }
        if sources_checked == 0:
            result["note"] = (
                "No reputation provider covering this IOC type responded "
                "(AbuseIPDB is IPs only; OTX requires OTX_API_KEY)"
            )
        return result
