"""STIX 2.1 format converter for IOC export."""

import json
from datetime import datetime, timezone
from typing import List, Dict, Any
from uuid import uuid4


STIX_IOC_TYPE_MAP = {
    "ip": "ipv4-addr",
    "domain": "domain-name",
    "url": "url",
    "hash": "file",
    "email": "email-addr",
}


def ioc_to_stix_indicator(ioc: Dict[str, Any]) -> Dict[str, Any]:
    """Convert an internal IOC dict to a STIX 2.1 Indicator object."""
    stix_type = STIX_IOC_TYPE_MAP.get(ioc.get("type"), "artifact")
    value = ioc.get("value", "")

    if ioc["type"] == "ip":
        pattern = f"[ipv4-addr:value = '{value}']"
    elif ioc["type"] == "domain":
        pattern = f"[domain-name:value = '{value}']"
    elif ioc["type"] == "url":
        pattern = f"[url:value = '{value}']"
    elif ioc["type"] == "hash":
        length = len(value)
        if length == 32:
            hash_type = "MD5"
        elif length == 40:
            hash_type = "SHA-1"
        else:
            hash_type = "SHA-256"
        pattern = f"[file:hashes.'{hash_type}' = '{value}']"
    elif ioc["type"] == "email":
        pattern = f"[email-addr:value = '{value}']"
    else:
        pattern = f"[artifact:payload_bin = '{value}']"

    score = ioc.get("threat_score", 0)
    if score >= 76:
        confidence = 85
    elif score >= 51:
        confidence = 65
    elif score >= 26:
        confidence = 40
    else:
        confidence = 15

    indicator = {
        "type": "indicator",
        "spec_version": "2.1",
        "id": f"indicator--{uuid4()}",
        "created": ioc.get("created_at", datetime.now(timezone.utc).isoformat()),
        "modified": ioc.get("updated_at", datetime.now(timezone.utc).isoformat()),
        "name": f"{ioc['type'].upper()} - {value}",
        "description": f"Threat indicator from SENTINEL TIP. Score: {score}/100",
        "indicator_types": _get_indicator_types(ioc),
        "pattern": pattern,
        "pattern_type": "stix",
        "valid_from": ioc.get("first_seen", datetime.now(timezone.utc).isoformat()),
        "confidence": confidence,
        "labels": ioc.get("tags", []),
    }

    return indicator


def _get_indicator_types(ioc: Dict[str, Any]) -> List[str]:
    """Determine STIX indicator types from IOC tags and metadata."""
    tags = [t.lower() for t in ioc.get("tags", [])]
    types = []

    if any(t in tags for t in ["malware", "ransomware", "trojan"]):
        types.append("malicious-activity")
    if any(t in tags for t in ["phishing", "phish"]):
        types.append("malicious-activity")
    if any(t in tags for t in ["c2", "c&c", "command-and-control"]):
        types.append("malicious-activity")
    if any(t in tags for t in ["botnet", "bot"]):
        types.append("malicious-activity")
    if any(t in tags for t in ["apt", "threat-actor"]):
        types.append("attribution")

    if not types:
        types.append("anomalous-activity")

    return types


def create_stix_bundle(iocs: List[Dict[str, Any]]) -> Dict[str, Any]:
    """Create a STIX 2.1 Bundle from a list of IOC dicts."""
    indicators = [ioc_to_stix_indicator(ioc) for ioc in iocs]

    bundle = {
        "type": "bundle",
        "id": f"bundle--{uuid4()}",
        "objects": indicators,
    }

    return bundle


def export_stix_json(iocs: List[Dict[str, Any]]) -> str:
    """Export IOCs as a STIX 2.1 JSON string."""
    bundle = create_stix_bundle(iocs)
    return json.dumps(bundle, indent=2, default=str)
