"""Contact form API endpoints."""

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy import select, func
from sqlalchemy.ext.asyncio import AsyncSession

from app.database import get_db
from app.models.contact import Contact
from app.schemas.contact import ContactCreate, ContactResponse, ContactListResponse

import structlog

router = APIRouter()
logger = structlog.get_logger()


@router.post("/submit", response_model=ContactResponse, status_code=201)
async def submit_contact(
    data: ContactCreate,
    db: AsyncSession = Depends(get_db)
):
    """Submit a new contact form message."""
    try:
        # Create new contact record
        contact = Contact(
            name=data.name,
            email=data.email,
            reason=data.reason.value,  # Convert enum to string
            ioc=data.ioc,
            message=data.message,
            is_resolved="pending"
        )
        
        db.add(contact)
        await db.commit()
        await db.refresh(contact)
        
        logger.info(
            "contact_submitted",
            contact_id=contact.id,
            email=contact.email,
            reason=contact.reason
        )
        
        return contact
    
    except Exception as e:
        logger.error("contact_submission_failed", error=str(e))
        await db.rollback()
        raise HTTPException(status_code=500, detail=f"Failed to submit contact form: {str(e)}")


@router.get("/messages", response_model=ContactListResponse)
async def list_contacts(
    page: int = 1,
    page_size: int = 50,
    status: str = None,
    db: AsyncSession = Depends(get_db)
):
    """List all contact messages (admin endpoint - should add auth later)."""
    # Calculate offset
    offset = (page - 1) * page_size
    
    # Build query
    query = select(Contact)
    
    if status:
        query = query.where(Contact.is_resolved == status)
    
    # Get total count
    count_query = select(func.count()).select_from(Contact)
    if status:
        count_query = count_query.where(Contact.is_resolved == status)
    
    total_result = await db.execute(count_query)
    total = total_result.scalar()
    
    # Get contacts with pagination
    query = query.order_by(Contact.created_at.desc()).offset(offset).limit(page_size)
    result = await db.execute(query)
    contacts = result.scalars().all()
    
    return ContactListResponse(
        contacts=contacts,
        total=total,
        page=page,
        page_size=page_size
    )


@router.get("/{contact_id}", response_model=ContactResponse)
async def get_contact(
    contact_id: str,
    db: AsyncSession = Depends(get_db)
):
    """Get a specific contact message by ID (admin endpoint - should add auth later)."""
    result = await db.execute(
        select(Contact).where(Contact.id == contact_id)
    )
    contact = result.scalar_one_or_none()
    
    if not contact:
        raise HTTPException(status_code=404, detail="Contact message not found")
    
    return contact


@router.patch("/{contact_id}/resolve")
async def resolve_contact(
    contact_id: str,
    notes: str = None,
    db: AsyncSession = Depends(get_db)
):
    """Mark a contact message as resolved (admin endpoint - should add auth later)."""
    result = await db.execute(
        select(Contact).where(Contact.id == contact_id)
    )
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
    
    logger.info(
        "contact_resolved",
        contact_id=contact.id,
        email=contact.email
    )
    
    return {"message": "Contact marked as resolved", "contact": contact}
