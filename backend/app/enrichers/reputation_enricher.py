"""Aggregate reputation enrichment."""

from typing import Dict, Any, Optional

from app.enrichers.base import BaseEnricher


class ReputationEnricher(BaseEnricher):
    name = "reputation"

    async def enrich(self, value: str, ioc_type: str) -> Optional[Dict[str, Any]]:
        return {
            "aggregate_score": 0,
            "sources_checked": 0,
            "sources_flagged": 0,
            "details": {},
            "note": "Configure API keys for live reputation data",
        }
