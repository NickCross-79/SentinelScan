"""Shared FastAPI dependencies."""

from __future__ import annotations

from collections.abc import Iterator

from fastapi import Depends, HTTPException, Request, status

from backend.app.core.security import origin_allowed
from backend.app.db.base import SessionLocal


def get_db() -> Iterator:
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


def enforce_origin(request: Request) -> None:
    if not origin_allowed(request):
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="origin not allowed")


OriginGuard = Depends(enforce_origin)
DbSession = Depends(get_db)
