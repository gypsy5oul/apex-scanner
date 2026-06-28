"""Async SQLAlchemy engine/session management.

Lazily builds a single async engine from ``settings.DATABASE_URL``. If the URL
is empty the DB layer stays dormant (returns None / ping() == False) so the app
runs exactly as before — Phase 1 only *connects*, it does not read or write.
"""
from typing import Optional

from sqlalchemy import text
from sqlalchemy.ext.asyncio import (
    create_async_engine, async_sessionmaker, AsyncEngine, AsyncSession,
)

from app.config import settings
from app.logging_config import get_logger

logger = get_logger(__name__)

_engine: Optional[AsyncEngine] = None
_sessionmaker: Optional[async_sessionmaker] = None


def get_engine() -> Optional[AsyncEngine]:
    """The shared async engine, or None when DATABASE_URL is not configured."""
    global _engine
    if _engine is None and settings.DATABASE_URL:
        _engine = create_async_engine(
            settings.DATABASE_URL,
            pool_size=settings.DB_POOL_SIZE,
            max_overflow=settings.DB_MAX_OVERFLOW,
            pool_pre_ping=True,
            future=True,
        )
    return _engine


def get_sessionmaker() -> Optional[async_sessionmaker]:
    global _sessionmaker
    if _sessionmaker is None:
        engine = get_engine()
        if engine is not None:
            _sessionmaker = async_sessionmaker(engine, expire_on_commit=False, class_=AsyncSession)
    return _sessionmaker


async def get_session():
    """FastAPI dependency yielding an AsyncSession (Phase 2+ will use this)."""
    sm = get_sessionmaker()
    if sm is None:
        raise RuntimeError("DATABASE_URL is not configured")
    async with sm() as session:
        yield session


async def ping() -> bool:
    """True if Postgres is reachable; False if not configured/unreachable."""
    engine = get_engine()
    if engine is None:
        return False
    async with engine.connect() as conn:
        await conn.execute(text("SELECT 1"))
    return True


async def dispose() -> None:
    global _engine, _sessionmaker
    if _engine is not None:
        await _engine.dispose()
    _engine = None
    _sessionmaker = None
