"""
Wiestell — YARAify enricher.

Enriches SHA256 hash IOCs with YARA rule matches, ClamAV detections,
imphash, tlsh, and malware family classification.

Requires Auth-Key (same abuse.ch account as other feeds).
SHA256 ONLY — cannot query MD5 or SHA1 hashes.

API docs: https://yaraify.abuse.ch/api/
"""

import logging
import re
from typing import Any, Optional

from app.enrichers.base import BaseEnricher

logger = logging.getLogger(__name__)

_YARAIFY_API_URL = "https://yaraify-api.abuse.ch/api/v1/"
_SUPPORTED_TYPES = {"hash"}
_SHA256_LEN = 64

# Strip common prefixes/suffixes from YARA rule names to extract malware family
_YARA_PREFIX_RE = re.compile(r"^(MALW_|win_|linux_|osx_|elf_)", re.IGNORECASE)
_YARA_SUFFIX_RE = re.compile(r"(_auto|_w\d+|_\d+)$", re.IGNORECASE)


class YARAifyEnricher(BaseEnricher):
    """YARAify enricher for SHA256 hash IOCs."""

    name = "yaraify"
    cache_ttl = 43200  # 12 hours

    def __init__(self, api_key: str) -> None:
        self.api_key = api_key

    def supports(self, ioc_type: str) -> bool:
        return ioc_type in _SUPPORTED_TYPES

    async def enrich(self, value: str, ioc_type: str) -> Optional[dict[str, Any]]:
        """Query YARAify for the given hash.

        Returns None for non-SHA256 hashes (MD5/SHA1 cannot be queried).
        Never raises — errors returned as {"source": "yaraify", "error": "..."}.
        """
        # SHA256 only — skip MD5 (32), SHA1 (40), SHA512 (128)
        if len(value) != _SHA256_LEN:
            return None

        import httpx

        try:
            async with httpx.AsyncClient(timeout=30.0) as client:
                resp = await client.post(
                    _YARAIFY_API_URL,
                    json={"query": "search_hash", "search_term": value},
                    headers={"Auth-Key": self.api_key},
                )
                resp.raise_for_status()
                body = resp.json()
                return self._extract(body)

        except Exception as exc:
            logger.warning("YARAify enrichment failed for %s: %s", value, exc)
            return {"source": "yaraify", "error": str(exc)}

    def _extract(self, body: dict) -> dict[str, Any]:
        """Extract enrichment fields from YARAify response."""
        data_list = body.get("data") or []
        if not data_list:
            return {"source": "yaraify", "found": False}

        entry = data_list[0]

        # YARA rule names
        yara_rules: list[str] = []
        for result in entry.get("static_results") or []:
            rule_name = result.get("rule_name", "")
            if rule_name:
                yara_rules.append(rule_name)

        # ClamAV detections
        clamav = entry.get("clamav_results") or []

        # Malware families extracted from YARA rule names
        families: set[str] = set()
        for rule in yara_rules:
            family = _YARA_PREFIX_RE.sub("", rule)
            family = _YARA_SUFFIX_RE.sub("", family)
            if family:
                families.add(family.lower())

        return {
            "source": "yaraify",
            # YARAify holds this sample, so all three signals were answered. Zero rule
            # hits is a negative verdict, not silence.
            "assessed": ["yara_rules", "clamav", "malware_families"],
            "yaraify_yara_rules": yara_rules,
            "yaraify_clamav": clamav,
            "yaraify_imphash": entry.get("imphash"),
            "yaraify_tlsh": entry.get("tlsh"),
            "yaraify_file_type": entry.get("mime_type"),
            "yaraify_file_size": entry.get("file_size"),
            "yaraify_first_seen": entry.get("first_seen"),
            "yaraify_malware_families": sorted(families),
        }