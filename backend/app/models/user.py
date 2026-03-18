"""User database model."""

import uuid
from datetime import datetime, timezone

from sqlalchemy import Column, String, Boolean, DateTime

from app.database import Base


class User(Base):
    __tablename__ = "users"

    id = Column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    username = Column(String(100), unique=True, nullable=False)
    email = Column(String(255), unique=True, nullable=False)
    hashed_password = Column(String(255), nullable=False)
    full_name = Column(String(200))
    role = Column(String(50), default="analyst")  # admin, analyst, viewer
    is_active = Column(Boolean, default=True)
    created_at = Column(DateTime, default=lambda: datetime.now(timezone.utc).replace(tzinfo=None))
    last_login = Column(DateTime)

    def __repr__(self):
        return f"<User(username={self.username}, role={self.role})>"
