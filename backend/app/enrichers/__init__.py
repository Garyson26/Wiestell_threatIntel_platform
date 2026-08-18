"""Enricher registry — the single source of truth for enrichment sources.

Every enricher is a :class:`~app.enrichers.base.BaseEnricher` subclass listed in
:func:`build_registry`. ``supports()`` decides which IOC types a source applies
to and ``cache_ttl`` decides how long a stored result stays fresh, so
``app.services.enrichment_engine`` needs no per-source knowledge: adding an
enricher means adding one line here.

Registration order matters — it determines the order sources are attempted and
reported for an IOC.

Enrichers whose credentials are absent are not registered at all, so an
unconfigured source never appears applicable and never stores an
``{"error": "no api key"}`` row against every IOC. Shodan is the deliberate
exception: it stays registered and returns an explanatory payload, preserving
long-standing behaviour that the dashboard relies on.

Gated as of 2026-07-30: ``malwarebazaar``. abuse.ch now requires an Auth-Key on
its JSON query APIs, so the previously "optional" key is mandatory — see the
comment at its registration below.

Gated as of 2026-07-31: ``geoip``. Its "credential" is the MaxMind ``.mmdb`` file,
which is fetched by a build step that fails open, so it is frequently absent — and
while absent the enricher wrote an ``error_city`` row against every IP IOC.
"""

from typing import Dict, List, Optional

import structlog

from app.config import settings
from app.enrichers.base import BaseEnricher

logger = structlog.get_logger()

_registry: Optional[Dict[str, BaseEnricher]] = None


def _geoip_database_available() -> bool:
    """Whether the MaxMind .mmdb GeoIP requires is actually present and readable.

    Read at registry-build time, not import time, so ``reset_registry()`` picks up a
    changed ``GEOIP_DB_PATH``. A missing file is logged once here rather than once per
    IP lookup.
    """
    import os

    path = settings.GEOIP_DB_PATH
    if path and os.path.isfile(path):
        return True
    logger.warning(
        "geoip_database_missing",
        path=path,
        detail=(
            "GeoIP enrichment is disabled: the MaxMind database file is absent. It is "
            "downloaded at build time by download_geolite2.py, which requires "
            "MAXMIND_ACCOUNT_ID and MAXMIND_LICENSE_KEY. Every IP IOC will be enriched "
            "without country or ASN data until it is present."
        ),
    )
    return False


def _shodan_library_available() -> bool:
    """Whether the `shodan` package can actually be imported.

    Checked with `find_spec` rather than a real import so building the registry does not
    pull a heavyweight dependency into every process that merely asks what enrichers
    exist. `find_spec` raises ModuleNotFoundError for a missing PARENT package, so the
    call is guarded rather than trusted to return None.
    """
    from importlib.util import find_spec

    try:
        return find_spec("shodan") is not None
    except (ImportError, ValueError):
        return False


def build_registry() -> Dict[str, BaseEnricher]:
    """Instantiate every enricher whose configuration requirements are met."""
    from app.enrichers.cvedetails_enricher import CVEDetailsEnricher
    from app.enrichers.dns_enricher import DNSEnricher
    from app.enrichers.geoip_enricher import GeoIPEnricher
    from app.enrichers.malwarebazaar_enricher import MalwareBazaarEnricher
    from app.enrichers.nvd_enricher import NVDEnricher
    from app.enrichers.reputation_enricher import ReputationEnricher
    from app.enrichers.shodan_enricher import ShodanEnricher
    from app.enrichers.whois_enricher import WhoisEnricher
    from app.enrichers.yaraify_enricher import YARAifyEnricher

    registry: Dict[str, BaseEnricher] = {}

    def add(enricher: BaseEnricher) -> None:
        registry[enricher.name] = enricher

    # ── Always available (no credentials required; degrade gracefully) ────────
    # GeoIP is gated **in its original registration position** on the MaxMind database
    # file existing, so the attempt order pinned by
    # tests/test_enrichers.py::TestEngineDispatch is unchanged whenever it is present.
    #
    # The .mmdb file is this enricher's credential — it is the only thing that lets it
    # answer — so the rule in the module docstring applies to it. Without the file,
    # `geoip2.database.Reader` raises for every lookup and the enricher stored
    # {"error_city": "GeoIP city database not available"} against *every* IP IOC, which
    # is exactly what gating exists to prevent.
    #
    # It is absent more often than it looks. The file is not committed; it is fetched at
    # build time by `render.yaml` and `render-build.sh` with
    # `python download_geolite2.py || echo "...continuing anyway"`, and the script needs
    # MAXMIND_ACCOUNT_ID and MAXMIND_LICENSE_KEY. So a deploy without those credentials
    # fails open and silently loses geo enrichment for the entire IP population — see
    # PROJECT_SUMMARY.md §8 item 14 for the build-step and /health follow-ups.
    if _geoip_database_available():
        add(GeoIPEnricher())
    add(WhoisEnricher())
    add(DNSEnricher())
    add(ReputationEnricher())     # skips providers whose keys are unset
    # SHODAN IS GATED ON THE LIBRARY BEING IMPORTABLE, since 2026-08-17. It used to be
    # registered unconditionally as the documented exception to the gating rule, on the
    # grounds that it "stays registered and returns an explanatory payload, preserving
    # pre-existing dashboard behaviour".
    #
    # THE EXCEPTION WAS RETIRED BECAUSE ITS PREMISE STOPPED HOLDING. An explanatory
    # payload is useful when the reader could plausibly act on it — "add a key". But
    # `shodan` is commented out of requirements.txt ("not compatible with Vercel
    # serverless (no binary wheels)") and is not pulled in transitively, so in the
    # deployed environment the payload is {"error": "Shodan library not installed"} even
    # when the key IS set. That is not explanatory, it is misleading: it points an
    # operator at the credential when the package is the problem.
    #
    # Measured cost of leaving it: 5,947 rows, 12.4% of the enrichment table, none of
    # which have ever carried data — and each with a 6-hour expires_at, so Section E's
    # refresh selection would re-attempt every one of them four times a day forever.
    #
    # The key check stays inside enrich() as a second barrier: importable but
    # unconfigured is a real state locally, and there the explanatory payload IS
    # actionable.
    if _shodan_library_available():
        add(ShodanEnricher())

    # MalwareBazaar is credential-gated **in its original registration position**,
    # so the attempt order pinned by tests/test_enrichers.py::TestEngineDispatch is
    # unchanged whenever a key is set.
    #
    # It used to be registered unconditionally with the note "abuse.ch key is
    # optional". That is no longer true, verified 2026-07-30: an unauthenticated
    # POST to https://mb-api.abuse.ch/api/v1/ returns HTTP 401
    # {"error": "Unauthorized"}. The enricher calls raise_for_status(), so without a
    # key it stored {"found": false, "error": "...401..."} against *every* hash IOC
    # — exactly what gating exists to prevent.
    #
    # There is no unauthenticated per-hash lookup. The bulk CSV at
    # bazaar.abuse.ch/export/csv/recent/ is still open (HTTP 200) but cannot answer
    # "tell me about this specific hash", which is what enrichment needs. So the key
    # is genuinely required and the gate is correct rather than conservative.
    if settings.MALWAREBAZAAR_API_KEY:
        add(MalwareBazaarEnricher())

    # NVD works without a key (5 requests/30s); a key raises that to 50/30s.
    add(NVDEnricher(api_key=settings.NVD_API_KEY or None))

    # ── Credential-gated ─────────────────────────────────────────────────────
    if settings.CVEDETAILS_ACCESS_TOKEN:
        add(CVEDetailsEnricher(access_token=settings.CVEDETAILS_ACCESS_TOKEN))

    # YARAify uses an abuse.ch Auth-Key — the same account as MalwareBazaar.
    yaraify_key = settings.YARAIFY_API_KEY or settings.MALWAREBAZAAR_API_KEY
    if yaraify_key:
        add(YARAifyEnricher(api_key=yaraify_key))

    logger.info("enricher_registry_built", enrichers=list(registry))
    return registry


def get_registry() -> Dict[str, BaseEnricher]:
    """Return the process-wide registry, building it on first use."""
    global _registry
    if _registry is None:
        _registry = build_registry()
    return _registry


def get_enricher(source: str) -> Optional[BaseEnricher]:
    """Look up a registered enricher by its ``name``."""
    return get_registry().get(source)


def applicable_sources(ioc_type: str) -> List[str]:
    """Registered enricher names that apply to ``ioc_type``, in registry order."""
    return [
        name
        for name, enricher in get_registry().items()
        if enricher.supports(ioc_type)
    ]


def reset_registry() -> None:
    """Drop the cached registry (used after configuration changes in tests)."""
    global _registry
    _registry = None


__all__ = [
    "BaseEnricher",
    "applicable_sources",
    "build_registry",
    "get_enricher",
    "get_registry",
    "reset_registry",
]
