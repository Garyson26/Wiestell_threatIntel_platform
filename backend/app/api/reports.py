"""Report generation API endpoints."""

from uuid import UUID
from fastapi import APIRouter, Depends, HTTPException
from fastapi.responses import PlainTextResponse
from sqlalchemy import select, desc
from sqlalchemy.ext.asyncio import AsyncSession

from app.database import get_db
from app.models.report import Report
from app.schemas.report import ReportCreate, ReportResponse, ReportListResponse
from app.services.report_generator import generate_daily_brief, generate_custom_report

router = APIRouter()


@router.get("", response_model=ReportListResponse)
async def list_reports(db: AsyncSession = Depends(get_db)):
    """List all generated reports."""
    result = await db.execute(
        select(Report).order_by(desc(Report.generated_at)).limit(50)
    )
    reports = result.scalars().all()
    return ReportListResponse(
        items=[ReportResponse.model_validate(r) for r in reports],
        total=len(reports),
    )


@router.post("/generate", response_model=ReportResponse)
async def generate_report(request: ReportCreate, db: AsyncSession = Depends(get_db)):
    """Generate a custom threat report."""
    content = await generate_custom_report(
        session=db,
        title=request.title,
        date_from=request.date_from,
        date_to=request.date_to,
        ioc_ids=request.ioc_ids,
        min_score=request.min_score,
        feed_sources=request.feed_sources,
    )

    result = await db.execute(
        select(Report).order_by(desc(Report.generated_at)).limit(1)
    )
    report = result.scalar_one_or_none()
    if report:
        return ReportResponse.model_validate(report)
    raise HTTPException(status_code=500, detail="Report generation failed")


@router.get("/daily-brief", response_model=ReportResponse)
async def get_daily_brief(db: AsyncSession = Depends(get_db)):
    """Get or generate the daily threat brief."""
    report = await generate_daily_brief(db)
    return ReportResponse.model_validate(report)


@router.get("/{report_id}/download")
async def download_report(report_id: UUID, db: AsyncSession = Depends(get_db)):
    """Download a report as a plain text file."""
    result = await db.execute(select(Report).where(Report.id == report_id))
    report = result.scalar_one_or_none()
    if not report:
        raise HTTPException(status_code=404, detail="Report not found")

    lines = [
        report.title,
        "=" * len(report.title),
        f"Type: {report.report_type}",
        f"Generated: {report.generated_at.strftime('%Y-%m-%d %H:%M UTC')}",
        "",
    ]

    if report.summary:
        lines += [report.summary, ""]

    content = report.content or {}

    if "summary" in content:
        lines.append("--- Summary ---")
        for key, val in content["summary"].items():
            lines.append(f"  {key}: {val}")
        lines.append("")

    if "top_threats" in content:
        lines.append("--- Top Threats ---")
        for t in content["top_threats"]:
            tags = ", ".join(t.get("tags", []))
            lines.append(f"  [{t.get('category', '').upper()}] {t['type']}:{t['value']}  score={t.get('score')}  tags={tags}")
        lines.append("")

    if "ioc_type_distribution" in content:
        lines.append("--- IOC Type Distribution ---")
        for ioc_type, count in content["ioc_type_distribution"].items():
            lines.append(f"  {ioc_type}: {count}")
        lines.append("")

    if "feed_status" in content:
        lines.append("--- Feed Status ---")
        for f in content["feed_status"]:
            lines.append(f"  {f['name']}: {f.get('status', 'unknown')} (IOCs: {f.get('ioc_count', 0)})")
        lines.append("")

    if "iocs" in content:
        lines.append(f"--- IOCs ({content.get('total_iocs', len(content['iocs']))}) ---")
        for ioc in content["iocs"]:
            tags = ", ".join(ioc.get("tags", []))
            lines.append(f"  [{ioc.get('category', '').upper()}] {ioc['type']}:{ioc['value']}  score={ioc.get('score')}  tags={tags}")
        lines.append("")

    if "period" in content:
        lines.append(f"Period: {content['period'].get('from', '')} to {content['period'].get('to', '')}")

    text = "\n".join(lines)
    filename = f"{report.report_type}_{report.generated_at.strftime('%Y%m%d')}.txt"
    return PlainTextResponse(
        content=text,
        headers={"Content-Disposition": f'attachment; filename="{filename}"'},
    )


@router.get("/{report_id}", response_model=ReportResponse)
async def get_report(report_id: UUID, db: AsyncSession = Depends(get_db)):
    """Get a specific report."""
    result = await db.execute(select(Report).where(Report.id == report_id))
    report = result.scalar_one_or_none()
    if not report:
        raise HTTPException(status_code=404, detail="Report not found")
    return ReportResponse.model_validate(report)
