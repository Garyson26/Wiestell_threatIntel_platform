"""AI-powered threat intelligence endpoints using Groq (Llama 3.3 70B)."""

from datetime import datetime, timezone, timedelta
from typing import List, Optional
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel
from sqlalchemy import select, func, desc
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import selectinload

from app.database import get_db
from app.models.ioc import IOC
from app.models.report import Report
from app.services.groq_service import groq_service

router = APIRouter()


# --- Request/Response Schemas ---


class ChatMessage(BaseModel):
    role: str  # "user" or "assistant"
    content: str


class ChatRequest(BaseModel):
    messages: List[ChatMessage]
    context: Optional[str] = None


class ChatResponse(BaseModel):
    response: str


class AIAnalysisResponse(BaseModel):
    analysis: str
    summary: str
    risk_level: str
    recommendations: List[str]


class AIStatusResponse(BaseModel):
    available: bool
    model: str


# --- Endpoints ---


@router.get("/status", response_model=AIStatusResponse)
async def ai_status():
    """Check if the AI service is configured and available."""
    return AIStatusResponse(
        available=groq_service.is_available,
        model="llama-3.3-70b-versatile",
    )


@router.post("/analyze/{ioc_id}", response_model=AIAnalysisResponse)
async def analyze_ioc(ioc_id: UUID, db: AsyncSession = Depends(get_db)):
    """Generate AI threat analysis for a specific IOC."""
    if not groq_service.is_available:
        raise HTTPException(status_code=503, detail="AI service not configured. Set GROQ_API_KEY.")

    result = await db.execute(
        select(IOC).options(selectinload(IOC.enrichments)).where(IOC.id == ioc_id)
    )
    ioc = result.scalar_one_or_none()
    if not ioc:
        raise HTTPException(status_code=404, detail="IOC not found")

    enrichment_data = [
        {"source": e.source, "data": e.data, "enriched_at": str(e.enriched_at)}
        for e in (ioc.enrichments or [])
    ]

    try:
        analysis = await groq_service.analyze_ioc(
            ioc_type=ioc.type,
            ioc_value=ioc.value,
            enrichment_data=enrichment_data if enrichment_data else None,
        )
    except ValueError as e:
        raise HTTPException(status_code=503, detail=str(e))
    except Exception as e:
        detail = str(e)
        if "429" in detail or "quota" in detail.lower():
            raise HTTPException(status_code=429, detail="Groq API rate limit exceeded. Please wait a moment and try again.")
        raise HTTPException(status_code=500, detail=f"AI analysis failed: {detail}")

    return AIAnalysisResponse(
        analysis=analysis.get("analysis", ""),
        summary=analysis.get("summary", ""),
        risk_level=analysis.get("risk_level", "medium"),
        recommendations=analysis.get("recommendations", []),
    )


@router.post("/chat", response_model=ChatResponse)
async def chat(request: ChatRequest):
    """Chat with the AI threat intelligence assistant."""
    if not groq_service.is_available:
        raise HTTPException(status_code=503, detail="AI service not configured. Set GROQ_API_KEY.")

    if not request.messages:
        raise HTTPException(status_code=400, detail="Messages list cannot be empty")

    messages = [{"role": m.role, "content": m.content} for m in request.messages]

    try:
        response = await groq_service.chat(
            messages=messages,
            system_context=request.context,
        )
    except ValueError as e:
        raise HTTPException(status_code=503, detail=str(e))
    except Exception as e:
        detail = str(e)
        if "429" in detail or "quota" in detail.lower():
            raise HTTPException(status_code=429, detail="Groq API rate limit exceeded. Please wait a moment and try again.")
        raise HTTPException(status_code=500, detail=f"AI chat failed: {detail}")

    return ChatResponse(response=response)


@router.post("/report")
async def generate_ai_report(db: AsyncSession = Depends(get_db)):
    """Generate an AI-written threat intelligence report."""
    if not groq_service.is_available:
        raise HTTPException(status_code=503, detail="AI service not configured. Set GROQ_API_KEY.")

    now = datetime.now(timezone.utc)
    yesterday = now - timedelta(days=1)

    # Gather stats
    total_result = await db.execute(select(func.count(IOC.id)))
    total_iocs = total_result.scalar() or 0

    new_result = await db.execute(
        select(func.count(IOC.id)).where(IOC.created_at >= yesterday)
    )
    new_count = new_result.scalar() or 0

    # Get critical IOCs
    critical_result = await db.execute(
        select(IOC)
        .where(IOC.threat_score >= 70)
        .order_by(desc(IOC.threat_score))
        .limit(30)
    )
    critical_iocs = critical_result.scalars().all()

    ioc_data = [
        {
            "type": ioc.type,
            "value": ioc.value,
            "threat_score": ioc.threat_score,
            "tags": ioc.tags or [],
            "first_seen": str(ioc.first_seen) if ioc.first_seen else None,
            "last_seen": str(ioc.last_seen) if ioc.last_seen else None,
        }
        for ioc in critical_iocs
    ]

    stats = {
        "total_iocs": total_iocs,
        "new_iocs_24h": new_count,
        "critical_iocs": len(critical_iocs),
        "report_date": now.isoformat(),
    }

    try:
        ai_result = await groq_service.generate_ai_report(
            ioc_data=ioc_data,
            stats=stats,
        )
    except ValueError as e:
        raise HTTPException(status_code=503, detail=str(e))
    except Exception as e:
        detail = str(e)
        if "429" in detail or "quota" in detail.lower():
            raise HTTPException(status_code=429, detail="Groq API rate limit exceeded. Please wait a moment and try again.")
        raise HTTPException(status_code=500, detail=f"AI report generation failed: {detail}")

    # Store as a Report
    report = Report(
        title=ai_result["title"],
        report_type="ai_insight",
        summary="AI-generated threat intelligence brief powered by Groq.",
        content={"ai_report": ai_result["content"], **stats},
        parameters={"generated_by": "llama-3.3-70b-versatile"},
        generated_at=now,
        created_by="SENTINEL AI",
    )
    db.add(report)
    await db.flush()

    from app.schemas.report import ReportResponse
    return ReportResponse.model_validate(report)
