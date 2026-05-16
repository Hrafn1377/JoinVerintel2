import uuid
from sqlalchemy import Column, String, Boolean, DateTime, Float, JSON, Text, ForeignKey
from sqlalchemy.orm import relationship
from sqlalchemy.sql import func
from app.db.session import Base


class User(Base):
    __tablename__ = "users"

    id = Column(String, primary_key=True, default=lambda: str(uuid.uuid4()))
    email = Column(String, unique=True, nullable=False, index=True)
    hashed_password = Column(String, nullable=True)
    is_active = Column(Boolean, default=True)
    created_at = Column(DateTime, server_default=func.now())

    verifications = relationship("Verification", back_populates="user")


class Verification(Base):
    __tablename__ = "verifications"

    id = Column(String, primary_key=True, default=lambda: str(uuid.uuid4()))
    user_id = Column(String, ForeignKey("users.id"), nullable=True)
    posting_text = Column(Text, nullable=False)
    company_name = Column(String, nullable=True)
    company_domain = Column(String, nullable=True)
    company_phone = Column(String, nullable=True)
    claimed_country = Column(String, nullable=True, default="us")
    overall_score = Column(Float, nullable=True)
    verification_status = Column(String, nullable=True)
    singals = Column(JSON, nullable=True)
    created_at = Column(DateTime, server_default=func.now())

    user = relationship("User", back_populates="verifications")