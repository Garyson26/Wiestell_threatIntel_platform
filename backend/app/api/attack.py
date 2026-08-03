"""MITRE ATT&CK mapping API endpoints."""

from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy import select, func
from sqlalchemy.ext.asyncio import AsyncSession

from app.database import get_db
from app.models.attack_technique import AttackTechnique
from app.models.ioc import IOC

router = APIRouter()


def _has_technique(technique_id: str):
    """Filter IOCs whose mitre_techniques JSON array contains ``technique_id``.

    ``mitre_techniques`` is a JSON column on MySQL, so the PostgreSQL ARRAY
    operators (``.any()`` / ``.overlap()``) are unavailable — using them raised
    at query build time. json_contains is the portable MySQL equivalent and
    matches how app/api/ioc.py filters the same column.
    """
    return func.json_contains(IOC.mitre_techniques, func.json_quote(technique_id)) == 1


MITRE_TACTICS_ORDER = [
    "Reconnaissance",
    "Resource Development",
    "Initial Access",
    "Execution",
    "Persistence",
    "Privilege Escalation",
    "Defense Evasion",
    "Credential Access",
    "Discovery",
    "Lateral Movement",
    "Collection",
    "Command and Control",
    "Exfiltration",
    "Impact",
]


@router.get("/matrix")
async def get_attack_matrix(db: AsyncSession = Depends(get_db)):
    """Get full ATT&CK matrix with IOC counts per technique."""
    result = await db.execute(select(AttackTechnique).order_by(AttackTechnique.tactic))
    techniques = result.scalars().all()

    matrix = {}
    for tactic in MITRE_TACTICS_ORDER:
        matrix[tactic] = []

    for tech in techniques:
        ioc_count_result = await db.execute(
            select(func.count(IOC.id)).where(_has_technique(tech.id))
        )
        ioc_count = ioc_count_result.scalar() or 0

        entry = {
            "id": tech.id,
            "name": tech.name,
            "tactic": tech.tactic,
            "ioc_count": ioc_count,
            "url": tech.url,
        }

        if tech.tactic in matrix:
            matrix[tech.tactic].append(entry)
        else:
            matrix[tech.tactic] = [entry]

    return matrix


@router.get("/techniques/{technique_id}")
async def get_technique_detail(technique_id: str, db: AsyncSession = Depends(get_db)):
    """Get technique detail with associated IOCs."""
    result = await db.execute(
        select(AttackTechnique).where(AttackTechnique.id == technique_id)
    )
    technique = result.scalar_one_or_none()
    if not technique:
        raise HTTPException(status_code=404, detail="Technique not found")

    iocs = await db.execute(
        select(IOC)
        .where(_has_technique(technique_id))
        .order_by(IOC.threat_score.desc())
        .limit(50)
    )
    associated_iocs = iocs.scalars().all()

    return {
        "id": technique.id,
        "name": technique.name,
        "tactic": technique.tactic,
        "description": technique.description,
        "url": technique.url,
        "data_sources": technique.data_sources or [],
        "associated_iocs": [
            {
                "id": str(ioc.id),
                "type": ioc.type,
                "value": ioc.value,
                "threat_score": ioc.threat_score,
                "tags": ioc.tags or [],
            }
            for ioc in associated_iocs
        ],
    }


@router.get("/heatmap")
async def get_heatmap(
    min_score: int = Query(0, ge=0, le=100),
    db: AsyncSession = Depends(get_db),
):
    """Get heatmap data for the ATT&CK matrix visualization."""
    result = await db.execute(select(AttackTechnique))
    techniques = result.scalars().all()

    heatmap = []
    for tech in techniques:
        ioc_count_result = await db.execute(
            select(func.count(IOC.id)).where(
                _has_technique(tech.id),
                IOC.threat_score >= min_score,
            )
        )
        count = ioc_count_result.scalar() or 0

        heatmap.append({
            "technique_id": tech.id,
            "technique_name": tech.name,
            "tactic": tech.tactic,
            "ioc_count": count,
            "intensity": min(1.0, count / 50) if count > 0 else 0,
        })

    return heatmap
