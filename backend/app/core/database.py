"""Database connection and session management.

Uses SQLAlchemy 2.0 async engine with PostgreSQL.
For local development without PostgreSQL, falls back to SQLite.
"""

from __future__ import annotations

from contextlib import asynccontextmanager
from typing import AsyncGenerator

from sqlalchemy.ext.asyncio import (
    AsyncEngine,
    AsyncSession,
    async_sessionmaker,
    create_async_engine,
)
from sqlalchemy.orm import DeclarativeBase

from backend.app.core.config import get_settings
from backend.app.core.logging import get_logger

logger = get_logger(__name__)


class Base(DeclarativeBase):
    """SQLAlchemy declarative base for all models."""
    pass


# Module-level engine and session factory
_engine: AsyncEngine | None = None
_session_factory: async_sessionmaker[AsyncSession] | None = None


def get_engine() -> AsyncEngine:
    """Get or create the database engine.

    Returns:
        The SQLAlchemy async engine.
    """
    global _engine
    if _engine is None:
        settings = get_settings()
        db_url = settings.database.url

        # For SQLite async support
        if "sqlite" in db_url:
            db_url = db_url.replace("sqlite://", "sqlite+aiosqlite://")

        _engine = create_async_engine(
            db_url,
            echo=settings.database.echo,
            pool_pre_ping=True,
        )
        logger.info("Database engine created")
    return _engine


def get_session_factory() -> async_sessionmaker[AsyncSession]:
    """Get or create the session factory.

    Returns:
        Async session factory.
    """
    global _session_factory
    if _session_factory is None:
        engine = get_engine()
        _session_factory = async_sessionmaker(
            engine,
            class_=AsyncSession,
            expire_on_commit=False,
        )
    return _session_factory


@asynccontextmanager
async def get_db_session() -> AsyncGenerator[AsyncSession, None]:
    """Get a database session as an async context manager.

    Yields:
        An AsyncSession that auto-commits on success or rolls back on error.

    Example:
        async with get_db_session() as session:
            result = await session.execute(select(Model))
    """
    factory = get_session_factory()
    session = factory()
    try:
        yield session
        await session.commit()
    except Exception:
        await session.rollback()
        raise
    finally:
        await session.close()


async def init_db() -> None:
    """Initialize database tables.

    Creates all tables defined by Base metadata.
    For production, use Alembic migrations instead.
    """
    engine = get_engine()
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
    logger.info("Database tables initialized")


async def close_db() -> None:
    """Close the database engine and clean up connections."""
    global _engine, _session_factory
    if _engine is not None:
        await _engine.dispose()
        _engine = None
        _session_factory = None
        logger.info("Database engine disposed")
