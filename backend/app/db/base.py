"""SQLAlchemy engine, session factory, and declarative base."""

from __future__ import annotations

import uuid
from datetime import datetime, timezone

from sqlalchemy import DateTime, String, create_engine
from sqlalchemy.orm import DeclarativeBase, mapped_column, sessionmaker

from backend.app.config import settings

_connect_args = {"check_same_thread": False} if settings.database_url.startswith("sqlite") else {}
engine = create_engine(settings.database_url, connect_args=_connect_args, future=True)
SessionLocal = sessionmaker(bind=engine, autoflush=False, expire_on_commit=False, future=True)


class Base(DeclarativeBase):
    pass


def utcnow() -> datetime:
    return datetime.now(timezone.utc)


def new_uuid() -> str:
    return str(uuid.uuid4())


def uuid_pk():
    return mapped_column(String(36), primary_key=True, default=new_uuid)


def ts_column(**kw):
    return mapped_column(DateTime(timezone=True), default=utcnow, **kw)


def init_db() -> None:
    """Create tables. MVP uses create_all; production migrations via Alembic."""
    from backend.app.db import models  # noqa: F401  (register mappers)

    Base.metadata.create_all(bind=engine)
