"""IOC correlation engine for discovering relationships between indicators."""

from typing import List, Dict, Any, Optional
from datetime import datetime, timezone

from sqlalchemy import select, and_, or_
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.ioc import IOC
from app.models.ioc_relationship import IOCRelationship


async def find_correlations(
    session: AsyncSession,
    ioc: IOC,
) -> List[Dict[str, Any]]:
    """Find correlations between an IOC and other indicators in the database."""
    correlations = []

    if ioc.type == "domain":
        ip_correlations = await _correlate_domain_to_ips(session, ioc)
        correlations.extend(ip_correlations)

    elif ioc.type == "ip":
        domain_correlations = await _correlate_ip_to_domains(session, ioc)
        correlations.extend(domain_correlations)

    tag_correlations = await _correlate_by_tags(session, ioc)
    correlations.extend(tag_correlations)

    technique_correlations = await _correlate_by_mitre(session, ioc)
    correlations.extend(technique_correlations)

    return correlations


async def _correlate_domain_to_ips(session: AsyncSession, ioc: IOC) -> List[Dict]:
    """Find IPs that have been associated with a domain."""
    results = []
    query = select(IOC).where(
        and_(
            IOC.type == "ip",
            IOC.tags.overlap(ioc.tags) if ioc.tags else True,
        )
    ).limit(20)
    
    result = await session.execute(query)
    related_iocs = result.scalars().all()
    
    for related in related_iocs:
        if related.id != ioc.id:
            results.append({
                "target_ioc_id": str(related.id),
                "target_value": related.value,
                "target_type": related.type,
                "relationship_type": "resolves_to",
                "confidence": 60,
            })
    
    return results[:10]


async def _correlate_ip_to_domains(session: AsyncSession, ioc: IOC) -> List[Dict]:
    """Find domains associated with an IP."""
    results = []
    query = select(IOC).where(
        and_(
            IOC.type == "domain",
            IOC.tags.overlap(ioc.tags) if ioc.tags else True,
        )
    ).limit(20)
    
    result = await session.execute(query)
    related_iocs = result.scalars().all()
    
    for related in related_iocs:
        if related.id != ioc.id:
            results.append({
                "target_ioc_id": str(related.id),
                "target_value": related.value,
                "target_type": related.type,
                "relationship_type": "hosts",
                "confidence": 60,
            })
    
    return results[:10]


async def _correlate_by_tags(session: AsyncSession, ioc: IOC) -> List[Dict]:
    """Find IOCs sharing significant tags."""
    if not ioc.tags:
        return []

    significant_tags = [t for t in ioc.tags if t.lower() not in {"malware", "suspicious", "unknown"}]
    if not significant_tags:
        return []

    query = select(IOC).where(
        and_(
            IOC.id != ioc.id,
            IOC.tags.overlap(significant_tags),
        )
    ).order_by(IOC.threat_score.desc()).limit(10)

    result = await session.execute(query)
    related_iocs = result.scalars().all()

    return [
        {
            "target_ioc_id": str(r.id),
            "target_value": r.value,
            "target_type": r.type,
            "relationship_type": "associated_with",
            "confidence": 40,
        }
        for r in related_iocs
    ]


async def _correlate_by_mitre(session: AsyncSession, ioc: IOC) -> List[Dict]:
    """Find IOCs sharing MITRE ATT&CK techniques."""
    if not ioc.mitre_techniques:
        return []

    query = select(IOC).where(
        and_(
            IOC.id != ioc.id,
            IOC.mitre_techniques.overlap(ioc.mitre_techniques),
        )
    ).order_by(IOC.threat_score.desc()).limit(10)

    result = await session.execute(query)
    related_iocs = result.scalars().all()

    return [
        {
            "target_ioc_id": str(r.id),
            "target_value": r.value,
            "target_type": r.type,
            "relationship_type": "shares_technique",
            "confidence": 50,
        }
        for r in related_iocs
    ]


async def store_relationships(
    session: AsyncSession,
    source_ioc_id: str,
    correlations: List[Dict],
):
    """Store discovered correlations as IOC relationships."""
    for corr in correlations:
        existing = await session.execute(
            select(IOCRelationship).where(
                and_(
                    IOCRelationship.source_ioc_id == source_ioc_id,
                    IOCRelationship.target_ioc_id == corr["target_ioc_id"],
                    IOCRelationship.relationship_type == corr["relationship_type"],
                )
            )
        )
        if existing.scalar_one_or_none() is None:
            rel = IOCRelationship(
                source_ioc_id=source_ioc_id,
                target_ioc_id=corr["target_ioc_id"],
                relationship_type=corr["relationship_type"],
                confidence=corr.get("confidence", 50),
            )
            session.add(rel)

    await session.flush()
