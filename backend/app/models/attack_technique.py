"""MITRE ATT&CK Technique database model."""

from sqlalchemy import Column, String, Text
from sqlalchemy.dialects.postgresql import ARRAY

from app.database import Base


class AttackTechnique(Base):
    __tablename__ = "attack_techniques"

    id = Column(String(20), primary_key=True)  # T1566, T1190, etc.
    name = Column(String(200), nullable=False)
    tactic = Column(String(100), nullable=False)
    description = Column(Text)
    url = Column(Text)
    data_sources = Column(ARRAY(Text), default=list)

    def __repr__(self):
        return f"<AttackTechnique(id={self.id}, name={self.name})>"
