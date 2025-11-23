"""
Database configuration and session management.
Uses async SQLAlchemy with PostgreSQL (asyncpg driver).
"""

from typing import AsyncGenerator
from sqlalchemy.ext.asyncio import (
    AsyncEngine,
    AsyncSession,
    create_async_engine,
    async_sessionmaker,
)
from sqlalchemy.orm import declarative_base

from app.config import settings

# SQLAlchemy declarative base for ORM models
Base = declarative_base()

# Create async engine
# echo=False in production to reduce log noise
engine: AsyncEngine = create_async_engine(
    settings.database_url,
    echo=False,  # Set to True for SQL query debugging
    future=True,
    pool_pre_ping=True,  # Verify connections before using them
)

# Session factory for creating database sessions
AsyncSessionLocal = async_sessionmaker(
    engine,
    class_=AsyncSession,
    expire_on_commit=False,
    autocommit=False,
    autoflush=False,
)


async def get_db() -> AsyncGenerator[AsyncSession, None]:
    """
    FastAPI dependency for database sessions.
    
    Provides an async database session with automatic cleanup.
    Use with FastAPI's Depends() injection.
    
    Example:
        @app.get("/items")
        async def read_items(db: AsyncSession = Depends(get_db)):
            result = await db.execute(select(Item))
            return result.scalars().all()
    
    Yields:
        AsyncSession: Database session
    """
    async with AsyncSessionLocal() as session:
        try:
            yield session
        finally:
            await session.close()


async def create_tables():
    """
    Create all database tables defined in ORM models.
    
    This function should be called during application startup.
    In production, consider using Alembic for migrations instead.
    
    Security Note:
    Ensures all required tables exist before the API starts serving requests.
    """
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
