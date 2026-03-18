"""OTP database model."""

import uuid
from datetime import datetime, timezone

from sqlalchemy import Column, String, DateTime, ForeignKey

from app.database import Base


class OTP(Base):
    __tablename__ = "otps"

    id = Column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    user_id = Column(String(36), ForeignKey("users.id"), nullable=True)  # Nullable for signup OTPs
    email = Column(String(255), nullable=False, index=True)
    otp = Column(String(10), nullable=False)
    created_at = Column(DateTime, default=lambda: datetime.now(timezone.utc).replace(tzinfo=None))
    expires_at = Column(DateTime, nullable=False)
    verified = Column(String(10), default="pending")  # pending, verified, expired
    
    # Registration data (for signup OTPs only)
    username = Column(String(255), nullable=True)
    hashed_password = Column(String(255), nullable=True)
    full_name = Column(String(255), nullable=True)
    role = Column(String(50), nullable=True)

    def __repr__(self):
        return f"<OTP(email={self.email}, status={self.verified})>"
