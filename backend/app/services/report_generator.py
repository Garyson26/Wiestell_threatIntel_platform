"""Automated report generation service."""

from datetime import datetime, timezone, timedelta
from typing import Dict, Any, List, Optional
from uuid import UUID

from sqlalchemy import select, func, desc, Integer
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.ioc import IOC
from app.models.feed import FeedSource
from app.models.report import Report
from app.services.scoring_engine import get_score_category


async def generate_daily_brief(session: AsyncSession) -> Report:
    """Generate automated daily threat intelligence brief."""
    now = datetime.now(timezone.utc)
    yesterday = now - timedelta(days=1)

    total_iocs = await session.execute(select(func.count(IOC.id)))
    total = total_iocs.scalar() or 0

    new_iocs = await session.execute(
        select(func.count(IOC.id)).where(IOC.created_at >= yesterday)
    )
    new_count = new_iocs.scalar() or 0

    critical_iocs = await session.execute(
        select(IOC)
        .where(IOC.threat_score >= 76, IOC.last_seen >= yesterday)
        .order_by(desc(IOC.threat_score))
        .limit(20)
    )
    critical = critical_iocs.scalars().all()

    type_counts = await session.execute(
        select(IOC.type, func.count(IOC.id))
        .where(IOC.created_at >= yesterday)
        .group_by(IOC.type)
    )
    type_dist = {row[0]: row[1] for row in type_counts}

    score_dist = await session.execute(
        select(
            func.sum(func.cast(IOC.threat_score >= 76, Integer)).label("critical"),
            func.sum(func.cast(IOC.threat_score.between(51, 75), Integer)).label("high"),
            func.sum(func.cast(IOC.threat_score.between(26, 50), Integer)).label("medium"),
            func.sum(func.cast(IOC.threat_score < 26, Integer)).label("low"),
        ).where(IOC.created_at >= yesterday)
    )

    feeds = await session.execute(
        select(FeedSource).where(FeedSource.is_enabled == True)
    )
    active_feeds = feeds.scalars().all()

    content = {
        "period": {"from": yesterday.isoformat(), "to": now.isoformat()},
        "summary": {
            "total_iocs": total,
            "new_iocs_24h": new_count,
            "critical_count": len(critical),
        },
        "top_threats": [
            {
                "id": str(ioc.id),
                "type": ioc.type,
                "value": ioc.value,
                "score": ioc.threat_score,
                "category": get_score_category(ioc.threat_score),
                "tags": ioc.tags or [],
            }
            for ioc in critical
        ],
        "ioc_type_distribution": type_dist,
        "feed_status": [
            {
                "name": f.name,
                "status": f.last_sync_status or "unknown",
                "last_sync": f.last_sync_at.isoformat() if f.last_sync_at else None,
                "ioc_count": f.ioc_count,
            }
            for f in active_feeds
        ],
    }

    report = Report(
        title=f"Daily Threat Brief - {now.strftime('%Y-%m-%d')}",
        report_type="daily_brief",
        summary=f"SENTINEL Daily Brief: {new_count} new IOCs, {len(critical)} critical threats in the last 24 hours.",
        content=content,
        parameters={"date": now.isoformat()},
        generated_at=now,
    )
    session.add(report)
    await session.flush()

    return report


async def generate_custom_report(
    session: AsyncSession,
    title: str,
    date_from: Optional[datetime] = None,
    date_to: Optional[datetime] = None,
    ioc_ids: Optional[List[UUID]] = None,
    min_score: Optional[int] = None,
    feed_sources: Optional[List[str]] = None,
) -> Dict[str, Any]:
    """Generate a custom threat report based on filters."""
    query = select(IOC)
    
    if date_from:
        query = query.where(IOC.last_seen >= date_from)
    if date_to:
        query = query.where(IOC.last_seen <= date_to)
    if ioc_ids:
        query = query.where(IOC.id.in_(ioc_ids))
    if min_score is not None:
        query = query.where(IOC.threat_score >= min_score)
    
    query = query.order_by(desc(IOC.threat_score)).limit(200)
    
    result = await session.execute(query)
    iocs = result.scalars().all()

    content = {
        "title": title,
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "parameters": {
            "date_from": date_from.isoformat() if date_from else None,
            "date_to": date_to.isoformat() if date_to else None,
            "min_score": min_score,
        },
        "total_iocs": len(iocs),
        "iocs": [
            {
                "id": str(ioc.id),
                "type": ioc.type,
                "value": ioc.value,
                "score": ioc.threat_score,
                "category": get_score_category(ioc.threat_score),
                "tags": ioc.tags or [],
                "first_seen": ioc.first_seen.isoformat() if ioc.first_seen else None,
                "last_seen": ioc.last_seen.isoformat() if ioc.last_seen else None,
            }
            for ioc in iocs
        ],
    }

    report = Report(
        title=title,
        report_type="custom",
        summary=f"Custom report: {len(iocs)} IOCs matching filters.",
        content=content,
        parameters={
            "date_from": date_from.isoformat() if date_from else None,
            "date_to": date_to.isoformat() if date_to else None,
            "min_score": min_score,
        },
        generated_at=datetime.now(timezone.utc),
    )
    session.add(report)
    await session.flush()

    return content
