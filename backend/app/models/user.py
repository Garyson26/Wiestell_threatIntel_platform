"""User database model."""

import uuid
from datetime import datetime, timezone

from sqlalchemy import Column, String, Boolean, Integer

from app.database import Base
from app.models.types import NaiveUTCDateTime


class User(Base):
    __tablename__ = "users"

    id = Column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    username = Column(String(100), unique=True, nullable=False)
    email = Column(String(255), unique=True, nullable=False)
    hashed_password = Column(String(255), nullable=False)
    full_name = Column(String(200))
    role = Column(String(50), default="analyst")  # admin, analyst, viewer
    is_active = Column(Boolean, default=True)
    created_at = Column(NaiveUTCDateTime, default=lambda: datetime.now(timezone.utc).replace(tzinfo=None))
    last_login = Column(NaiveUTCDateTime)
    # Per-account password back-off (services/password_throttle.py, revision b8c9d0e10005).
    # NOT NULL with a server default: the compare-and-swap matches on equality, and
    # NULL = 0 is not true in SQL, so a NULL would lock every reservation out.
    failed_login_attempts = Column(Integer, nullable=False, default=0, server_default="0")
    locked_until = Column(NaiveUTCDateTime, nullable=True)

    def __repr__(self):
        return f"<User(username={self.username}, role={self.role})>"
