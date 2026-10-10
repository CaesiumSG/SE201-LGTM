"""Database models and session management for Shoply."""

from __future__ import annotations

import datetime

from sqlalchemy import (
    Column,
    DateTime,
    Float,
    ForeignKey,
    Integer,
    String,
    create_engine,
)
from sqlalchemy.orm import declarative_base, relationship, scoped_session, sessionmaker

Base = declarative_base()
SessionLocal = scoped_session(sessionmaker())
_engine = None


class User(Base):
    __tablename__ = "users"

    id = Column(Integer, primary_key=True)
    username = Column(String(80), unique=True, nullable=False)
    email = Column(String(255), unique=True, nullable=False)
    password_hash = Column(String(255), nullable=False)
    role = Column(String(20), nullable=False, default="user")  # user|manager|admin
    created_at = Column(DateTime, default=datetime.datetime.utcnow)

    orders = relationship("Order", back_populates="user")
    api_keys = relationship("ApiKey", back_populates="user")

    def to_dict(self, include_email: bool = False) -> dict:
        data = {"id": self.id, "username": self.username, "role": self.role}
        if include_email:
            data["email"] = self.email
        return data


class Order(Base):
    __tablename__ = "orders"

    id = Column(Integer, primary_key=True)
    user_id = Column(Integer, ForeignKey("users.id"), nullable=False)
    status = Column(String(20), nullable=False, default="pending")
    total = Column(Float, nullable=False, default=0.0)
    shipping_address = Column(String(500))
    created_at = Column(DateTime, default=datetime.datetime.utcnow)

    user = relationship("User", back_populates="orders")

    def to_dict(self) -> dict:
        return {
            "id": self.id,
            "user_id": self.user_id,
            "status": self.status,
            "total": self.total,
            "shipping_address": self.shipping_address,
        }


class ApiKey(Base):
    __tablename__ = "api_keys"

    id = Column(Integer, primary_key=True)
    key = Column(String(64), unique=True, nullable=False)
    user_id = Column(Integer, ForeignKey("users.id"), nullable=False)
    # Scopes: "reports:read", "orders:read", "orders:write"
    scope = Column(String(50), nullable=False, default="orders:read")
    created_at = Column(DateTime, default=datetime.datetime.utcnow)

    user = relationship("User", back_populates="api_keys")


class AuditLog(Base):
    __tablename__ = "audit_log"

    id = Column(Integer, primary_key=True)
    user_id = Column(Integer, ForeignKey("users.id"))
    action = Column(String(255), nullable=False)
    created_at = Column(DateTime, default=datetime.datetime.utcnow)


def init_db(database_url: str = "sqlite:///shoply.db"):
    """Create the engine, bind the session factory, create tables."""
    global _engine
    _engine = create_engine(database_url, future=True)
    SessionLocal.configure(bind=_engine)
    Base.metadata.create_all(_engine)
    return _engine


def get_engine():
    return _engine


def get_session():
    return SessionLocal()
