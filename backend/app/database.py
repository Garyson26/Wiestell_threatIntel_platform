"""Database connection and session management."""

import os
from sqlalchemy import create_engine, event, text
from sqlalchemy.ext.asyncio import AsyncSession, create_async_engine, async_sessionmaker
from sqlalchemy.orm import DeclarativeBase, sessionmaker
from sqlalchemy.pool import NullPool

from app.config import settings


def _patch_aiomysql() -> None:
    """Patch aiomysql.Connection.ensure_closed to handle already-closed TCP transports.

    When the MySQL server closes an idle connection (wait_timeout) while a
    transport reference is still held in the SQLAlchemy pool, aiomysql's
    ensure_closed() tries to write COM_QUIT to the dead uvloop TCPTransport
    and raises RuntimeError.  SQLAlchemy calls ensure_closed() from pool
    cleanup paths (_close_connection, reset_on_return) that do NOT go through
    the handle_error event, so the RuntimeError propagates all the way up to
    the caller.  Since the transport is already gone there is nothing to send,
    so silently swallowing the error is correct.
    """
    try:
        import aiomysql

        _orig_ensure_closed = aiomysql.Connection.ensure_closed

        async def _safe_ensure_closed(self):
            try:
                await _orig_ensure_closed(self)
            except RuntimeError as exc:
                if "TCPTransport" in str(exc) or "handler is closed" in str(exc):
                    pass  # transport already gone — nothing to close
                else:
                    raise

        aiomysql.Connection.ensure_closed = _safe_ensure_closed
    except ImportError:
        pass  # aiomysql not installed (e.g. pure-sync environments)


_patch_aiomysql()

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
    # Use a small pool so connections are reused across requests.
    # pool_pre_ping replaces NullPool's "fresh connection" safety: it validates
    # the connection before use and discards stale ones, without the cost of
    # opening a new TCP connection every single time.
    # pool_size + max_overflow kept low to stay well within shared-host limits.
    sync_engine = create_engine(
        settings.DATABASE_URL,
        pool_size=3,
        max_overflow=2,
        pool_recycle=280,    # discard before typical shared-host wait_timeout (300s)
        pool_pre_ping=True,  # validate connection health before use
        echo=False,
        connect_args={
            "connect_timeout": 30,
            "read_timeout": 60,
            "write_timeout": 60,
        }
    )
SyncSessionLocal = sessionmaker(bind=sync_engine)


def _set_mysql_session_timeouts(dbapi_connection, connection_record):
    """Raise MySQL session-level I/O timeouts on every new connection.

    The default net_read_timeout / net_write_timeout on shared MySQL hosts is
    often only 30-60 s.  Feed ingestion can hold a connection idle for several
    seconds between the initial SELECT and the subsequent flush+commit while
    Python computes threat scores.  Setting these to 300 s gives the session
    plenty of headroom and prevents error 2013 'Lost connection during query'.
    """
    cursor = dbapi_connection.cursor()
    cursor.execute(
        "SET SESSION net_read_timeout=300, net_write_timeout=300, wait_timeout=300"
    )
    cursor.close()


event.listen(sync_engine, "connect", _set_mysql_session_timeouts)

# Async engine (for FastAPI endpoints) - optimized for serverless
async_db_url = settings.DATABASE_ASYNC_URL or settings.DATABASE_URL.replace("mysql+pymysql://", "mysql+aiomysql://")

if IS_SERVERLESS:
    async_engine = create_async_engine(
        async_db_url,
        poolclass=NullPool,  # No connection pooling in serverless
        echo=False,
        connect_args={
            "connect_timeout": 10,
            "autocommit": False,
        }
    )
else:
    # Production pool — sized for high concurrency.
    # pool_size=10 + max_overflow=20 allows up to 30 simultaneous connections
    # without exhausting typical shared-host limits.
    # pool_recycle=1800 ensures connections are replaced well before the MySQL
    # server's wait_timeout closes them from the server side.
    # pool_pre_ping validates connection health before use so stale connections
    # are discarded transparently instead of raising OperationalError.
    async_engine = create_async_engine(
        async_db_url,
        pool_size=10,
        max_overflow=20,
        pool_recycle=1800,
        pool_pre_ping=True,
        pool_timeout=30,
        echo=False,
        connect_args={
            "connect_timeout": 30,
        }
    )

event.listen(async_engine.sync_engine, "connect", _set_mysql_session_timeouts)

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
            await session.commit()
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
