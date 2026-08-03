"""Contact form API endpoints.

``POST /submit`` is the only public route — it backs the marketing contact form.
Everything that reads or mutates the inbox requires an administrator.
"""

from typing import Optional

import structlog
from fastapi import APIRouter, Body, Depends, HTTPException, Query
from sqlalchemy import select, func
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.deps import rate_limit, require_admin
from app.database import get_db
from app.models.contact import Contact
from app.schemas.contact import ContactCreate, ContactResponse, ContactListResponse

router = APIRouter()
logger = structlog.get_logger()

ALLOWED_STATUSES = {"pending", "in-progress", "resolved"}


@router.post(
    "/submit",
    response_model=ContactResponse,
    status_code=201,
    dependencies=[Depends(rate_limit("contact-submit", max_requests=5, window_seconds=600))],
)
async def submit_contact(
    data: ContactCreate,
    db: AsyncSession = Depends(get_db),
):
    """Submit a new contact form message (public, rate limited)."""
    try:
        contact = Contact(
            name=data.name,
            email=data.email,
            reason=data.reason.value,  # Convert enum to string
            ioc=data.ioc,
            message=data.message,
            is_resolved="pending",
        )

        db.add(contact)
        await db.commit()
        await db.refresh(contact)

        logger.info("contact_submitted", contact_id=contact.id, reason=contact.reason)
        return contact

    except Exception as e:
        # Internal failure details stay in the log; the client gets a generic error.
        logger.error("contact_submission_failed", error=str(e), error_type=type(e).__name__)
        await db.rollback()
        raise HTTPException(status_code=500, detail="Failed to submit contact form")


@router.get("/messages", response_model=ContactListResponse, dependencies=[Depends(require_admin)])
async def list_contacts(
    page: int = Query(1, ge=1),
    page_size: int = Query(50, ge=1, le=200),
    status: Optional[str] = Query(None),
    db: AsyncSession = Depends(get_db),
):
    """List contact messages. Admin only."""
    if status is not None and status not in ALLOWED_STATUSES:
        raise HTTPException(
            status_code=400,
            detail=f"status must be one of: {', '.join(sorted(ALLOWED_STATUSES))}",
        )

    offset = (page - 1) * page_size

    query = select(Contact)
    count_query = select(func.count()).select_from(Contact)
    if status:
        query = query.where(Contact.is_resolved == status)
        count_query = count_query.where(Contact.is_resolved == status)

    total = (await db.execute(count_query)).scalar() or 0

    query = query.order_by(Contact.created_at.desc()).offset(offset).limit(page_size)
    contacts = (await db.execute(query)).scalars().all()

    return ContactListResponse(
        contacts=contacts,
        total=total,
        page=page,
        page_size=page_size,
    )


@router.get("/{contact_id}", response_model=ContactResponse, dependencies=[Depends(require_admin)])
async def get_contact(contact_id: str, db: AsyncSession = Depends(get_db)):
    """Get a specific contact message by ID. Admin only."""
    result = await db.execute(select(Contact).where(Contact.id == contact_id))
    contact = result.scalar_one_or_none()

    if not contact:
        raise HTTPException(status_code=404, detail="Contact message not found")

    return contact


@router.patch("/{contact_id}/resolve", dependencies=[Depends(require_admin)])
async def resolve_contact(
    contact_id: str,
    notes: Optional[str] = Body(None, max_length=2000, embed=True),
    db: AsyncSession = Depends(get_db),
):
    """Mark a contact message as resolved. Admin only."""
    result = await db.execute(select(Contact).where(Contact.id == contact_id))
    contact = result.scalar_one_or_none()

    if not contact:
        raise HTTPException(status_code=404, detail="Contact message not found")

    from datetime import datetime, timezone

    contact.is_resolved = "resolved"
    contact.resolved_at = datetime.now(timezone.utc).replace(tzinfo=None)
    if notes:
        contact.notes = notes

    await db.commit()
    await db.refresh(contact)

    logger.info("contact_resolved", contact_id=contact.id)

    return {"message": "Contact marked as resolved", "contact": ContactResponse.model_validate(contact)}
