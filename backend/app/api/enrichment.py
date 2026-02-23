"""Enrichment API endpoints."""

from uuid import UUID
from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.database import get_db
from app.models.ioc import IOC
from app.models.enrichment import Enrichment
from app.services.enrichment_engine import enrich_ioc
from app.schemas.enrichment import EnrichmentResponse, EnrichmentRequest

router = APIRouter()


@router.get("/{ioc_id}", response_model=list[EnrichmentResponse])
async def get_enrichments(ioc_id: UUID, db: AsyncSession = Depends(get_db)):
    """Get all enrichment data for an IOC."""
    result = await db.execute(
        select(Enrichment).where(Enrichment.ioc_id == ioc_id)
    )
    enrichments = result.scalars().all()
    return [EnrichmentResponse.model_validate(e) for e in enrichments]


@router.post("/{ioc_id}/enrich")
async def trigger_enrichment(
    ioc_id: UUID,
    request: EnrichmentRequest = EnrichmentRequest(),
    db: AsyncSession = Depends(get_db),
):
    """Trigger enrichment for an IOC with specified sources."""
    result = await db.execute(select(IOC).where(IOC.id == ioc_id))
    ioc = result.scalar_one_or_none()
    if not ioc:
        raise HTTPException(status_code=404, detail="IOC not found")

    results = await enrich_ioc(db, ioc, sources=request.sources)
    return {"status": "complete", "enrichments": results}
