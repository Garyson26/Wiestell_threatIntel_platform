"""Abstract base class for enrichment modules.

An enricher declares which IOC types it handles (:meth:`supports`), how long a
result stays fresh (:attr:`cache_ttl`) and how to fetch it (:meth:`enrich`).
Instances are registered in ``app.enrichers.build_registry()`` and dispatched by
``app.services.enrichment_engine``.

Contract for :meth:`enrich`:

* Return a dict to be stored as the enrichment payload for ``self.name``.
* Return ``None`` when the enricher cannot handle this specific value (e.g. a
  SHA256-only source given an MD5) — nothing is stored and nothing is cached.
* **Never raise.** Recoverable failures return ``{"error": "..."}`` so one
  unavailable source cannot fail the whole enrichment pass.
"""

import abc
from typing import Any, Dict, Optional


class BaseEnricher(abc.ABC):
    """Base contract for an enrichment source.

    ``enrich()`` must never raise. It returns a dict, ``None`` for "not applicable to
    this specific value", or ``{"error": ...}``.

    **The ``assessed`` key.** A returned dict should carry ``assessed``: a list of the
    signal names this call actually evaluated. ``scoring_engine.RISK_SIGNALS`` maps
    those names to their weight in the enrichment-risk denominator, and the scorer adds
    to that denominator *only* for declared names.

    This exists because key presence cannot express it. A key can be absent because
    the source said nothing, or present-but-empty because the source said "nothing
    found" — opposite answers with the same shape. Four separate defects came from the
    scorer guessing: provider silence read as clean, reverse DNS charging for a
    fast-flux signal it never carries, an NXDOMAIN domain looking identical to a
    resolved one (its ``records`` dict is truthy but every list inside is empty), and
    GeoIP's ``error_city`` slipping past a check for ``error``. All in the same
    direction: an absence scored as reassurance.

    Declare a signal when the source gave an answer about it — including a *negative*
    answer, which is real evidence. Omit it when the source was silent, unreachable or
    does not cover this indicator. Payloads without ``assessed`` fall back to
    ``scoring_engine._legacy_assessed``, which is permanent rather than transitional:
    cached enrichment rows are never refreshed on the cron path, so they do not age
    out. See that function's docstring.
    """

    """Abstract base enricher."""

    #: Stored in ``enrichments.source``; must be unique across enrichers.
    name: str = "unknown"

    #: Seconds a stored result stays valid before it is re-fetched.
    cache_ttl: int = 3600

    def supports(self, ioc_type: str) -> bool:
        """Whether this enricher applies to ``ioc_type``.

        Defaults to False so a subclass must opt in explicitly.
        """
        return False

    @abc.abstractmethod
    async def enrich(self, value: str, ioc_type: str) -> Optional[Dict[str, Any]]:
        """Perform enrichment on an IOC value."""
        ...
