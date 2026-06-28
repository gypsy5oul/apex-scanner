"""Synchronous SQLAlchemy engine for dual-writes.

The repositories are synchronous (called from both Celery tasks and — like the
existing sync Redis calls — FastAPI handlers), so the Phase-2 dual-write needs a
SYNC engine. We derive the sync URL from the async ``DATABASE_URL`` by swapping
the driver (``+asyncpg`` -> ``+psycopg``), so there is still a single env-driven
connection string.
"""
from typing import Optional

from sqlalchemy import create_engine
from sqlalchemy.engine import Engine
from sqlalchemy.orm import sessionmaker

from app.config import settings

_engine: Optional[Engine] = None
_Session: Optional[sessionmaker] = None


def _sync_url() -> str:
    url = settings.DATABASE_URL
    # async driver -> sync driver
    return url.replace("+asyncpg", "+psycopg")


def get_sync_engine() -> Optional[Engine]:
    global _engine
    if _engine is None and settings.DATABASE_URL:
        _engine = create_engine(
            _sync_url(),
            pool_size=5,
            max_overflow=10,
            pool_pre_ping=True,
            pool_timeout=5,
            future=True,
        )
    return _engine


def get_sync_session() -> Optional[sessionmaker]:
    global _Session
    if _Session is None:
        engine = get_sync_engine()
        if engine is not None:
            _Session = sessionmaker(engine, expire_on_commit=False)
    return _Session
