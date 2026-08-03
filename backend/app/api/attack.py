"""MITRE ATT&CK mapping API endpoints."""

import json
from collections import Counter
from typing import Optional

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


async def _technique_ioc_counts(
    db: AsyncSession, min_score: Optional[int] = None
) -> Counter:
    """IOC count per technique ID, in **one** statement.

    Replaces a ``COUNT`` per technique (Phase 5). The catalogue holds hundreds of
    techniques, so ``/attack/matrix`` and ``/attack/heatmap`` were issuing hundreds of
    round trips each — measured at 41 statements against the seeded test catalogue and
    proportionally worse in production. Latency is what makes that fatal rather than
    merely untidy: the app talks to the database across the public internet
    (Render → Hostinger, 50-300 ms) where a local container answers in ~0.1 ms, so the
    N+1 is nearly invisible in development and adds minutes in production.

    **Aggregated in Python from a single scan, deliberately not with a SQL join.** The
    obvious one-query form is

        SELECT t.id, COUNT(i.id) FROM attack_techniques t
        LEFT JOIN iocs i ON JSON_CONTAINS(i.mitre_techniques, JSON_QUOTE(t.id))
        GROUP BY t.id

    and it is one statement, but ``JSON_CONTAINS`` cannot use an index, so it degenerates
    to a cross product — hundreds of techniques × tens of thousands of IOCs, evaluated
    per pair, on a **shared** MySQL host this project does not have to itself. Fetching
    the technique arrays instead moves that work to the application: the arrays hold one
    to three short strings each, so the transfer is small and the counting is a linear
    pass. The trade is a little bandwidth for not putting a multi-million-comparison scan
    on a shared database.

    Counts each IOC **once per technique** even if its array repeats a value, matching
    what ``COUNT(IOC.id) WHERE json_contains(...)`` returned before.
    """
    stmt = select(IOC.mitre_techniques).where(
        # NULL yields NULL here, which fails the comparison, so untagged IOCs are
        # excluded in SQL rather than fetched and skipped in Python.
        func.json_length(IOC.mitre_techniques) > 0
    )
    if min_score:
        stmt = stmt.where(IOC.threat_score >= min_score)

    counts: Counter = Counter()
    for (techniques,) in (await db.execute(stmt)).all():
        if isinstance(techniques, str):
            # Defensive: a driver or column configuration that hands back raw JSON.
            try:
                techniques = json.loads(techniques)
            except (ValueError, TypeError):
                continue
        if not isinstance(techniques, (list, tuple)):
            continue
        counts.update({t for t in techniques if isinstance(t, str)})
    return counts


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

    # One statement for every technique's count, instead of one per technique.
    counts = await _technique_ioc_counts(db)

    matrix = {}
    for tactic in MITRE_TACTICS_ORDER:
        matrix[tactic] = []

    for tech in techniques:
        entry = {
            "id": tech.id,
            "name": tech.name,
            "tactic": tech.tactic,
            "ioc_count": counts.get(tech.id, 0),
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

    counts = await _technique_ioc_counts(db, min_score=min_score)

    heatmap = []
    for tech in techniques:
        count = counts.get(tech.id, 0)

        heatmap.append({
            "technique_id": tech.id,
            "technique_name": tech.name,
            "tactic": tech.tactic,
            "ioc_count": count,
            "intensity": min(1.0, count / 50) if count > 0 else 0,
        })

    return heatmap
