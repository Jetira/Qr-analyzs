"""
Async database layer using SQLAlchemy 2.x with PostgreSQL or SQLite.

This module sets up:
- Async engine for PostgreSQL (asyncpg driver) or SQLite (aiosqlite driver)
- AsyncSession factory
- FastAPI dependency for database sessions
- Base class for ORM models
"""

from typing import AsyncGenerator

from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine
from sqlalchemy.orm import DeclarativeBase

from app.config import get_settings

# Get database URL from settings
settings = get_settings()

# Determine if using SQLite or PostgreSQL
is_sqlite = settings.DATABASE_URL.startswith("sqlite")

# Create async engine
# For SQLite, we use aiosqlite driver
# For PostgreSQL, we use asyncpg driver
engine_kwargs = {
    "echo": False,  # Set to True for SQL query debugging
    "future": True,
}

# pool_pre_ping only for PostgreSQL
if not is_sqlite:
    engine_kwargs["pool_pre_ping"] = True

engine = create_async_engine(
    settings.DATABASE_URL,
    **engine_kwargs
)

# Create async session factory
# expire_on_commit=False prevents lazy-loading issues after commit
async_session_maker = async_sessionmaker(
    engine,
    class_=AsyncSession,
    expire_on_commit=False,
    autocommit=False,
    autoflush=False,
)


class Base(DeclarativeBase):
    """
    Base class for all ORM models.
    
    All models should inherit from this class to be part of the
    SQLAlchemy metadata and support migrations.
    """
    pass


async def get_db() -> AsyncGenerator[AsyncSession, None]:
    """
    FastAPI dependency for database sessions.
    
    Provides an async database session for each request.
    Automatically commits on success and rolls back on error.
    Always closes the session when done.
    
    Usage in FastAPI endpoints:
        @router.post("/example")
        async def example(db: AsyncSession = Depends(get_db)):
            # Use db session here
            pass
    
    Yields:
        AsyncSession: Database session for the current request.
    """
    async with async_session_maker() as session:
        try:
            yield session
            await session.commit()
        except Exception:
            await session.rollback()
            raise
        finally:
            await session.close()


async def init_db() -> None:
    """
    Initialize database tables.
    
    Creates all tables defined in the Base metadata.
    This is called on application startup.
    
    Note: In production, you should use a proper migration tool like Alembic.
    This function is provided for convenience during development.
    """
    async with engine.begin() as conn:
        # Create all tables
        await conn.run_sync(Base.metadata.create_all)
