"""IOC CRUD and search API endpoints."""

import csv
import io
from datetime import datetime
from typing import Optional, List
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, Query, Response
from sqlalchemy import select, func, desc, asc, or_, and_
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import selectinload

from app.database import get_db
from app.models.ioc import IOC
from app.models.enrichment import Enrichment
from app.models.ioc_source import IOCSource
from app.models.ioc_relationship import IOCRelationship
from app.schemas.ioc import (
    IOCCreate, IOCResponse, IOCDetailResponse, IOCSearchRequest,
    IOCBulkRequest, IOCExportRequest, IOCTagUpdate, PaginatedIOCResponse,
)
from app.services.scoring_engine import calculate_threat_score
from app.utils.ioc_validator import detect_ioc_type, validate_ioc, normalize_ioc
from app.utils.stix_converter import export_stix_json

router = APIRouter()


@router.get("", response_model=PaginatedIOCResponse)
async def list_iocs(
    page: int = Query(1, ge=1),
    page_size: int = Query(50, ge=1, le=500),
    ioc_type: Optional[str] = Query(None),
    min_score: Optional[int] = Query(None, ge=0, le=100),
    max_score: Optional[int] = Query(None, ge=0, le=100),
    sort_by: str = Query("last_seen"),
    sort_order: str = Query("desc"),
    tag: Optional[str] = Query(None),
    q: Optional[str] = Query(None),
    db: AsyncSession = Depends(get_db),
):
    """List IOCs with pagination, filtering, and sorting."""
    query = select(IOC)
    count_query = select(func.count(IOC.id))

    if ioc_type:
        query = query.where(IOC.type == ioc_type)
        count_query = count_query.where(IOC.type == ioc_type)
    if min_score is not None:
        query = query.where(IOC.threat_score >= min_score)
        count_query = count_query.where(IOC.threat_score >= min_score)
    if max_score is not None:
        query = query.where(IOC.threat_score <= max_score)
        count_query = count_query.where(IOC.threat_score <= max_score)
    if tag:
        query = query.where(IOC.tags.any(tag))
        count_query = count_query.where(IOC.tags.any(tag))
    if q:
        query = query.where(IOC.value.ilike(f"%{q}%"))
        count_query = count_query.where(IOC.value.ilike(f"%{q}%"))

    sort_column = getattr(IOC, sort_by, IOC.last_seen)
    if sort_order == "asc":
        query = query.order_by(asc(sort_column))
    else:
        query = query.order_by(desc(sort_column))

    total = (await db.execute(count_query)).scalar() or 0
    offset = (page - 1) * page_size
    query = query.offset(offset).limit(page_size)

    result = await db.execute(query)
    iocs = result.scalars().all()

    return PaginatedIOCResponse(
        items=[IOCResponse.model_validate(ioc) for ioc in iocs],
        total=total,
        page=page,
        page_size=page_size,
        pages=(total + page_size - 1) // page_size if page_size > 0 else 0,
    )


@router.get("/{ioc_id}", response_model=IOCDetailResponse)
async def get_ioc(ioc_id: UUID, db: AsyncSession = Depends(get_db)):
    """Get detailed IOC information including enrichment data."""
    result = await db.execute(
        select(IOC)
        .options(
            selectinload(IOC.enrichments),
            selectinload(IOC.sources).selectinload(IOCSource.feed),
        )
        .where(IOC.id == ioc_id)
    )
    ioc = result.scalar_one_or_none()

    if not ioc:
        raise HTTPException(status_code=404, detail="IOC not found")

    # Get relationships
    rels = await db.execute(
        select(IOCRelationship).where(
            or_(
                IOCRelationship.source_ioc_id == ioc_id,
                IOCRelationship.target_ioc_id == ioc_id,
            )
        )
    )
    relationships = rels.scalars().all()

    enrichments = [
        {"source": e.source, "data": e.data, "enriched_at": e.enriched_at.isoformat()}
        for e in ioc.enrichments
    ]

    sources = [
        {
            "feed_name": s.feed.name if s.feed else "Unknown",
            "feed_slug": s.feed.slug if s.feed else "unknown",
            "ingested_at": s.ingested_at.isoformat() if s.ingested_at else None,
        }
        for s in ioc.sources
    ]

    rel_data = []
    for r in relationships:
        is_source = str(r.source_ioc_id) == str(ioc_id)
        related_id = r.target_ioc_id if is_source else r.source_ioc_id
        related_result = await db.execute(select(IOC).where(IOC.id == related_id))
        related_ioc = related_result.scalar_one_or_none()
        if related_ioc:
            rel_data.append({
                "id": str(related_ioc.id),
                "type": related_ioc.type,
                "value": related_ioc.value,
                "threat_score": related_ioc.threat_score,
                "relationship_type": r.relationship_type,
                "direction": "outgoing" if is_source else "incoming",
            })

    # Build the response dict from the IOC base fields, then attach
    # manually-built enrichment/source/relationship dicts
    ioc_data = IOCResponse.model_validate(ioc).model_dump()
    ioc_data["enrichments"] = enrichments
    ioc_data["sources"] = sources
    ioc_data["relationships"] = rel_data

    return IOCDetailResponse.model_validate(ioc_data)


@router.post("", response_model=IOCResponse)
async def create_ioc(ioc_data: IOCCreate, db: AsyncSession = Depends(get_db)):
    """Submit a new IOC."""
    if not validate_ioc(ioc_data.type, ioc_data.value):
        detected = detect_ioc_type(ioc_data.value)
        if detected:
            ioc_data.type = detected
        else:
            raise HTTPException(status_code=400, detail=f"Invalid IOC format for type: {ioc_data.type}")

    value = normalize_ioc(ioc_data.value, ioc_data.type)

    existing = await db.execute(
        select(IOC).where(IOC.type == ioc_data.type, IOC.value == value)
    )
    if existing.scalar_one_or_none():
        raise HTTPException(status_code=409, detail="IOC already exists")

    score = ioc_data.threat_score
    if score is None:
        score = calculate_threat_score({
            "type": ioc_data.type,
            "value": value,
            "tags": ioc_data.tags,
            "mitre_techniques": ioc_data.mitre_techniques,
        })

    ioc = IOC(
        type=ioc_data.type,
        value=value,
        threat_score=score,
        confidence=ioc_data.confidence or 50,
        tags=ioc_data.tags,
        metadata_=ioc_data.metadata_ or {},
        mitre_techniques=ioc_data.mitre_techniques,
    )
    db.add(ioc)
    await db.flush()

    return IOCResponse.model_validate(ioc)


@router.post("/search", response_model=PaginatedIOCResponse)
async def search_iocs(search: IOCSearchRequest, db: AsyncSession = Depends(get_db)):
    """Advanced IOC search with multiple filters."""
    query = select(IOC)
    count_query = select(func.count(IOC.id))

    if search.query:
        query = query.where(IOC.value.ilike(f"%{search.query}%"))
        count_query = count_query.where(IOC.value.ilike(f"%{search.query}%"))
    if search.ioc_type:
        query = query.where(IOC.type == search.ioc_type)
        count_query = count_query.where(IOC.type == search.ioc_type)
    if search.min_score is not None:
        query = query.where(IOC.threat_score >= search.min_score)
        count_query = count_query.where(IOC.threat_score >= search.min_score)
    if search.max_score is not None:
        query = query.where(IOC.threat_score <= search.max_score)
        count_query = count_query.where(IOC.threat_score <= search.max_score)
    if search.tags:
        query = query.where(IOC.tags.overlap(search.tags))
        count_query = count_query.where(IOC.tags.overlap(search.tags))
    if search.mitre_technique:
        query = query.where(IOC.mitre_techniques.any(search.mitre_technique))
        count_query = count_query.where(IOC.mitre_techniques.any(search.mitre_technique))
    if search.date_from:
        query = query.where(IOC.last_seen >= search.date_from)
        count_query = count_query.where(IOC.last_seen >= search.date_from)
    if search.date_to:
        query = query.where(IOC.last_seen <= search.date_to)
        count_query = count_query.where(IOC.last_seen <= search.date_to)

    sort_column = getattr(IOC, search.sort_by, IOC.last_seen)
    if search.sort_order == "asc":
        query = query.order_by(asc(sort_column))
    else:
        query = query.order_by(desc(sort_column))

    total = (await db.execute(count_query)).scalar() or 0
    offset = (search.page - 1) * search.page_size
    query = query.offset(offset).limit(search.page_size)

    result = await db.execute(query)
    iocs = result.scalars().all()

    return PaginatedIOCResponse(
        items=[IOCResponse.model_validate(ioc) for ioc in iocs],
        total=total,
        page=search.page,
        page_size=search.page_size,
        pages=(total + search.page_size - 1) // search.page_size if search.page_size > 0 else 0,
    )


@router.post("/bulk", response_model=List[IOCResponse])
async def bulk_lookup(request: IOCBulkRequest, db: AsyncSession = Depends(get_db)):
    """Bulk IOC lookup — search for multiple IOC values at once."""
    results = []
    for value in request.values[:100]:  # Limit to 100
        value = value.strip()
        if not value:
            continue
        result = await db.execute(select(IOC).where(IOC.value == value))
        ioc = result.scalar_one_or_none()
        if ioc:
            results.append(IOCResponse.model_validate(ioc))
    return results


@router.put("/{ioc_id}/tags", response_model=IOCResponse)
async def update_tags(ioc_id: UUID, tag_update: IOCTagUpdate, db: AsyncSession = Depends(get_db)):
    """Update IOC tags."""
    result = await db.execute(select(IOC).where(IOC.id == ioc_id))
    ioc = result.scalar_one_or_none()
    if not ioc:
        raise HTTPException(status_code=404, detail="IOC not found")

    ioc.tags = tag_update.tags
    await db.flush()
    return IOCResponse.model_validate(ioc)


@router.get("/{ioc_id}/enrichment")
async def get_enrichment(ioc_id: UUID, db: AsyncSession = Depends(get_db)):
    """Get enrichment data for an IOC."""
    result = await db.execute(
        select(Enrichment).where(Enrichment.ioc_id == ioc_id)
    )
    enrichments = result.scalars().all()
    return [
        {
            "id": str(e.id),
            "source": e.source,
            "data": e.data,
            "enriched_at": e.enriched_at.isoformat(),
            "expires_at": e.expires_at.isoformat() if e.expires_at else None,
        }
        for e in enrichments
    ]


@router.post("/{ioc_id}/enrich")
async def trigger_enrichment(ioc_id: UUID, db: AsyncSession = Depends(get_db)):
    """Trigger re-enrichment for an IOC."""
    from app.services.enrichment_engine import enrich_ioc

    result = await db.execute(select(IOC).where(IOC.id == ioc_id))
    ioc = result.scalar_one_or_none()
    if not ioc:
        raise HTTPException(status_code=404, detail="IOC not found")

    enrichment_results = await enrich_ioc(db, ioc)
    return {"status": "enrichment_complete", "results": enrichment_results}


@router.get("/{ioc_id}/relationships")
async def get_relationships(ioc_id: UUID, db: AsyncSession = Depends(get_db)):
    """Get related IOCs."""
    result = await db.execute(
        select(IOCRelationship).where(
            or_(
                IOCRelationship.source_ioc_id == ioc_id,
                IOCRelationship.target_ioc_id == ioc_id,
            )
        )
    )
    relationships = result.scalars().all()

    rel_data = []
    for r in relationships:
        is_source = str(r.source_ioc_id) == str(ioc_id)
        related_id = r.target_ioc_id if is_source else r.source_ioc_id
        related = await db.execute(select(IOC).where(IOC.id == related_id))
        related_ioc = related.scalar_one_or_none()
        if related_ioc:
            rel_data.append({
                "id": str(related_ioc.id),
                "type": related_ioc.type,
                "value": related_ioc.value,
                "threat_score": related_ioc.threat_score,
                "relationship_type": r.relationship_type,
                "confidence": r.confidence,
                "direction": "outgoing" if is_source else "incoming",
            })

    return rel_data


@router.get("/{ioc_id}/timeline")
async def get_timeline(ioc_id: UUID, db: AsyncSession = Depends(get_db)):
    """Get IOC timeline showing history across sources."""
    result = await db.execute(
        select(IOCSource)
        .options(selectinload(IOCSource.feed))
        .where(IOCSource.ioc_id == ioc_id)
        .order_by(desc(IOCSource.ingested_at))
    )
    sources = result.scalars().all()

    ioc_result = await db.execute(select(IOC).where(IOC.id == ioc_id))
    ioc = ioc_result.scalar_one_or_none()
    if not ioc:
        raise HTTPException(status_code=404, detail="IOC not found")

    timeline = []
    if ioc.first_seen:
        timeline.append({
            "event": "first_seen",
            "timestamp": ioc.first_seen.isoformat(),
            "detail": "First observed in the wild",
        })

    for s in sources:
        timeline.append({
            "event": "ingested",
            "timestamp": s.ingested_at.isoformat() if s.ingested_at else None,
            "detail": f"Reported by {s.feed.name}" if s.feed else "Reported by unknown feed",
            "feed": s.feed.slug if s.feed else None,
        })

    return sorted(timeline, key=lambda x: x.get("timestamp", ""), reverse=True)


@router.post("/export")
async def export_iocs(request: IOCExportRequest, db: AsyncSession = Depends(get_db)):
    """Export IOCs in various formats (JSON, CSV, STIX)."""
    if request.ioc_ids:
        result = await db.execute(select(IOC).where(IOC.id.in_(request.ioc_ids)))
    else:
        query = select(IOC).order_by(desc(IOC.threat_score)).limit(1000)
        result = await db.execute(query)

    iocs = result.scalars().all()
    ioc_dicts = [
        {
            "id": str(ioc.id),
            "type": ioc.type,
            "value": ioc.value,
            "threat_score": ioc.threat_score,
            "confidence": ioc.confidence,
            "first_seen": ioc.first_seen.isoformat() if ioc.first_seen else None,
            "last_seen": ioc.last_seen.isoformat() if ioc.last_seen else None,
            "sighting_count": ioc.sighting_count,
            "tags": ioc.tags or [],
            "created_at": ioc.created_at.isoformat() if ioc.created_at else None,
            "updated_at": ioc.updated_at.isoformat() if ioc.updated_at else None,
        }
        for ioc in iocs
    ]

    if request.format == "stix":
        stix_json = export_stix_json(ioc_dicts)
        return Response(
            content=stix_json,
            media_type="application/json",
            headers={"Content-Disposition": "attachment; filename=sentinel_export.stix.json"},
        )
    elif request.format == "csv":
        output = io.StringIO()
        writer = csv.DictWriter(output, fieldnames=["type", "value", "threat_score", "confidence", "first_seen", "last_seen", "tags"])
        writer.writeheader()
        for d in ioc_dicts:
            d["tags"] = "|".join(d.get("tags", []))
            writer.writerow({k: d.get(k) for k in writer.fieldnames})
        return Response(
            content=output.getvalue(),
            media_type="text/csv",
            headers={"Content-Disposition": "attachment; filename=sentinel_export.csv"},
        )
    else:
        return ioc_dicts
