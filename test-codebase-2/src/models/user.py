"""User and subscription SQLAlchemy models."""
from datetime import datetime
from sqlalchemy import Column, String, Boolean, DateTime, Numeric, Enum, ForeignKey
from sqlalchemy.orm import relationship
import enum

from src.core.database import Base


class SubscriptionTier(str, enum.Enum):
    free = "free"
    pro = "pro"
    enterprise = "enterprise"


class User(Base):
    __tablename__ = "users"

    id = Column(String, primary_key=True)
    email = Column(String, unique=True, nullable=False, index=True)
    hashed_password = Column(String, nullable=False)
    is_active = Column(Boolean, default=True)
    is_superuser = Column(Boolean, default=False)
    stripe_customer_id = Column(String, unique=True)
    subscription_tier = Column(Enum(SubscriptionTier), default=SubscriptionTier.free)
    created_at = Column(DateTime, default=datetime.utcnow)

    invoices = relationship("Invoice", back_populates="user")
    payments = relationship("Payment", back_populates="user")


class Invoice(Base):
    __tablename__ = "invoices"

    id = Column(String, primary_key=True)
    user_id = Column(String, ForeignKey("users.id"), nullable=False)
    amount = Column(Numeric(10, 2), nullable=False)
    currency = Column(String, default="usd")
    status = Column(String, default="pending")   # pending | paid | void
    stripe_invoice_id = Column(String, unique=True)
    s3_key = Column(String)                       # path to PDF in S3
    created_at = Column(DateTime, default=datetime.utcnow)

    user = relationship("User", back_populates="invoices")


class Payment(Base):
    __tablename__ = "payments"

    id = Column(String, primary_key=True)
    user_id = Column(String, ForeignKey("users.id"), nullable=False)
    stripe_payment_intent_id = Column(String, unique=True)
    amount = Column(Numeric(10, 2), nullable=False)
    currency = Column(String, default="usd")
    status = Column(String)  # requires_payment_method | processing | succeeded | failed
    created_at = Column(DateTime, default=datetime.utcnow)

    user = relationship("User", back_populates="payments")
