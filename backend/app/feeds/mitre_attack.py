"""MITRE ATT&CK data loader."""

from typing import Any, List, Dict

import httpx
import structlog

logger = structlog.get_logger()

MITRE_STIX_URL = "https://raw.githubusercontent.com/mitre/cti/master/enterprise-attack/enterprise-attack.json"


async def load_attack_data() -> List[Dict[str, Any]]:
    """Load MITRE ATT&CK Enterprise techniques from the STIX repository."""
    techniques = []

    try:
        async with httpx.AsyncClient(timeout=60.0) as client:
            response = await client.get(MITRE_STIX_URL)
            response.raise_for_status()
            data = response.json()

        objects = data.get("objects", [])

        tactic_map = {}
        for obj in objects:
            if obj.get("type") == "x-mitre-tactic":
                short_name = obj.get("x_mitre_shortname", "")
                name = obj.get("name", "")
                tactic_map[short_name] = name

        for obj in objects:
            if obj.get("type") != "attack-pattern":
                continue
            if obj.get("revoked") or obj.get("x_mitre_deprecated"):
                continue

            ext_refs = obj.get("external_references", [])
            technique_id = None
            url = None
            for ref in ext_refs:
                if ref.get("source_name") == "mitre-attack":
                    technique_id = ref.get("external_id")
                    url = ref.get("url")
                    break

            if not technique_id:
                continue

            # Skip sub-techniques for cleaner matrix
            if "." in technique_id:
                continue

            kill_chain = obj.get("kill_chain_phases", [])
            tactic = "Unknown"
            for phase in kill_chain:
                if phase.get("kill_chain_name") == "mitre-attack":
                    phase_name = phase.get("phase_name", "")
                    tactic = tactic_map.get(phase_name, phase_name.replace("-", " ").title())
                    break

            techniques.append({
                "id": technique_id,
                "name": obj.get("name", ""),
                "tactic": tactic,
                "description": (obj.get("description", "") or "")[:500],
                "url": url,
                "data_sources": [
                    ds.get("name", "") if isinstance(ds, dict) else str(ds)
                    for ds in (obj.get("x_mitre_data_sources") or [])
                ],
            })

        logger.info("mitre_attack_loaded", technique_count=len(techniques))

    except Exception as e:
        logger.error("mitre_attack_load_error", error=str(e))

    return techniques
