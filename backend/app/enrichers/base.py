"""Abstract base class for enrichment modules."""

import abc
from typing import Dict, Any, Optional


class BaseEnricher(abc.ABC):
    """Abstract base enricher."""

    name: str = "unknown"

    @abc.abstractmethod
    async def enrich(self, value: str, ioc_type: str) -> Optional[Dict[str, Any]]:
        """Perform enrichment on an IOC value."""
        ...
