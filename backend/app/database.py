"""Database connection and session management."""

import os
from sqlalchemy import create_engine
from sqlalchemy.ext.asyncio import AsyncSession, create_async_engine, async_sessionmaker
from sqlalchemy.orm import DeclarativeBase, sessionmaker
from sqlalchemy.pool import NullPool

from app.config import settings

# Detect serverless environment
IS_SERVERLESS = os.getenv("VERCEL") or os.getenv("AWS_LAMBDA_FUNCTION_NAME")

# Sync engine (for Alembic migrations and Celery tasks)
if IS_SERVERLESS:
    sync_engine = create_engine(
        settings.DATABASE_URL,
        poolclass=NullPool,  # No pooling in serverless
        echo=False,
        connect_args={
            "connect_timeout": 10,
            "read_timeout": 30,
            "write_timeout": 30,
        }
    )
else:
    sync_engine = create_engine(
        settings.DATABASE_URL,
        pool_size=5,
        max_overflow=0,
        pool_pre_ping=True,
        pool_recycle=300,
        echo=False,
    )
SyncSessionLocal = sessionmaker(bind=sync_engine)

# Async engine (for FastAPI endpoints) - optimized for serverless
async_db_url = settings.DATABASE_ASYNC_URL or settings.DATABASE_URL.replace("mysql+pymysql://", "mysql+aiomysql://")

if IS_SERVERLESS:
    async_engine = create_async_engine(
        async_db_url,
        poolclass=NullPool,  # No connection pooling in serverless
        echo=False,
        connect_args={
            "connect_timeout": 10,
            "read_timeout": 30,
            "write_timeout": 30,
            "autocommit": False,
        }
    )
else:
    async_engine = create_async_engine(
        async_db_url,
        pool_size=2,
        max_overflow=1,
        pool_pre_ping=True,
        pool_recycle=300,
        echo=False,
    )

AsyncSessionLocal = async_sessionmaker(
    bind=async_engine,
    class_=AsyncSession,
    expire_on_commit=False,
)


class Base(DeclarativeBase):
    pass


async def get_db() -> AsyncSession:
    """Dependency that yields an async database session."""
    async with AsyncSessionLocal() as session:
        try:
            yield session
        except Exception as e:
            await session.rollback()
            raise
        finally:
            await session.close()


def get_sync_db():
    """Get a sync database session for Celery tasks."""
    session = SyncSessionLocal()
    try:
        yield session
        session.commit()
    except Exception:
        session.rollback()
        raise
    finally:
        session.close()
