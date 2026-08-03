"""OTP database model.

The ``otp`` column stores a keyed SHA-256 digest of the code (see
``app.api.users._hash_otp``), never the code itself, so a database read cannot
be replayed as a valid one-time password.
"""

import uuid
from datetime import datetime, timezone

from sqlalchemy import Column, String, ForeignKey, Integer

from app.database import Base
from app.models.types import NaiveUTCDateTime


class OTP(Base):
    __tablename__ = "otps"

    id = Column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    user_id = Column(String(36), ForeignKey("users.id"), nullable=True)  # Nullable for signup OTPs
    email = Column(String(255), nullable=False, index=True)
    otp = Column(String(255), nullable=False)  # keyed hash of the code
    purpose = Column(String(20), nullable=False, default="login")  # login, signup, password_reset
    attempts = Column(Integer, nullable=False, default=0)
    created_at = Column(NaiveUTCDateTime, default=lambda: datetime.now(timezone.utc).replace(tzinfo=None))
    expires_at = Column(NaiveUTCDateTime, nullable=False)
    verified = Column(String(10), default="pending")  # pending, verified, expired, locked

    # Registration data (for signup OTPs only)
    username = Column(String(255), nullable=True)
    hashed_password = Column(String(255), nullable=True)
    full_name = Column(String(255), nullable=True)
    role = Column(String(50), nullable=True)

    def __repr__(self):
        return f"<OTP(email={self.email}, purpose={self.purpose}, status={self.verified})>"
