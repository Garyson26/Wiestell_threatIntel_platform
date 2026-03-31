"""Database retry utilities for handling MySQL InnoDB lock contention.

MySQL InnoDB uses row-level locking. Under high concurrency two error codes
can surface when a transaction cannot acquire a lock in time:

  1205  ER_LOCK_WAIT_TIMEOUT  — a transaction waited longer than
                                innodb_lock_wait_timeout for a row-level lock
                                held by another transaction.
  1213  ER_LOCK_DEADLOCK      — the lock manager broke a circular wait by
                                rolling back one of the involved transactions.

Both are *transient*: the appropriate response is to roll back the failed
transaction and retry after a short back-off delay. This module provides
decorators and a helper function that implement that strategy for both
synchronous (Celery / SQLAlchemy-core) and async (FastAPI / async SQLAlchemy)
call sites.

Usage (sync decorator)::

    @retry_on_lock_timeout(max_retries=3, base_delay=1.0)
    def write_batch(session, rows):
        try:
            ...
            session.commit()
        except Exception:
            session.rollback()
            raise  # decorator catches and retries retryable errors

Usage (async decorator)::

    @async_retry_on_lock_timeout(max_retries=3, base_delay=1.0)
    async def write_batch(session, rows):
        try:
            ...
            await session.commit()
        except Exception:
            await session.rollback()
            raise

Usage (inline helper)::

    from app.utils.db_retry import is_retryable_lock_error
    ...
    except Exception as exc:
        session.rollback()
        if not is_retryable_lock_error(exc) or attempt == max_retries:
            raise
"""

import asyncio
import functools
import logging
import time
from typing import Callable

from sqlalchemy.exc import OperationalError

logger = logging.getLogger(__name__)

# InnoDB error codes that are safe to retry after a full rollback.
_RETRYABLE_MYSQL_CODES: frozenset = frozenset({
    1205,  # ER_LOCK_WAIT_TIMEOUT – waited too long for a row-level lock
    1213,  # ER_LOCK_DEADLOCK     – InnoDB broke a circular wait chain
})

_DEFAULT_MAX_RETRIES: int = 3
_DEFAULT_BASE_DELAY: float = 1.0  # seconds; doubles on each subsequent attempt


def is_retryable_lock_error(exc: BaseException) -> bool:
    """Return True if *exc* is a transient InnoDB lock contention error.

    Handles both SQLAlchemy ``OperationalError`` (which wraps the raw DB-API
    error in ``exc.orig``) and bare PyMySQL / MySQLdb errors propagated
    without the SQLAlchemy wrapper.
    """
    # SQLAlchemy wraps DB-API errors: check exc.orig first.
    if isinstance(exc, OperationalError):
        orig = getattr(exc, "orig", None)
        if orig is not None:
            code = getattr(orig, "args", (None,))[0]
            return code in _RETRYABLE_MYSQL_CODES

    # Bare DB-API error (e.g. raised by a raw connection or unwrapped).
    code = getattr(exc, "args", (None,))[0]
    return code in _RETRYABLE_MYSQL_CODES


def retry_on_lock_timeout(
    max_retries: int = _DEFAULT_MAX_RETRIES,
    base_delay: float = _DEFAULT_BASE_DELAY,
) -> Callable:
    """Decorator: retry a *sync* function on MySQL lock timeout or deadlock.

    Exponential back-off: delay = base_delay * 2^attempt (1 s, 2 s, 4 s …).

    The decorated function **must** roll back its own session before re-raising
    so the next attempt starts from a clean transaction state. The decorator
    will only retry errors where ``is_retryable_lock_error`` returns True.

    Example::

        @retry_on_lock_timeout(max_retries=3, base_delay=1.0)
        def update_iocs(session, mappings):
            try:
                session.bulk_update_mappings(IOC, mappings)
                session.commit()
            except Exception:
                session.rollback()
                raise
    """
    def decorator(func: Callable) -> Callable:
        @functools.wraps(func)
        def wrapper(*args, **kwargs):
            last_exc = None
            for attempt in range(max_retries + 1):
                try:
                    return func(*args, **kwargs)
                except Exception as exc:
                    if not is_retryable_lock_error(exc) or attempt == max_retries:
                        raise
                    last_exc = exc
                    delay = base_delay * (2 ** attempt)
                    logger.warning(
                        "db_lock_retry_sync: attempt %d/%d, sleeping %.1f s — %s",
                        attempt + 1,
                        max_retries,
                        delay,
                        str(exc),
                    )
                    time.sleep(delay)
            raise last_exc  # unreachable; satisfies type-checkers
        return wrapper
    return decorator


def async_retry_on_lock_timeout(
    max_retries: int = _DEFAULT_MAX_RETRIES,
    base_delay: float = _DEFAULT_BASE_DELAY,
) -> Callable:
    """Decorator: retry an *async* function on MySQL lock timeout or deadlock.

    Same exponential back-off strategy as ``retry_on_lock_timeout``. The
    decorated coroutine must roll back its own session before re-raising.

    Example::

        @async_retry_on_lock_timeout(max_retries=3, base_delay=1.0)
        async def update_iocs(session, mappings):
            try:
                await session.execute(sa_update(IOC), mappings)
                await session.commit()
            except Exception:
                await session.rollback()
                raise
    """
    def decorator(func: Callable) -> Callable:
        @functools.wraps(func)
        async def wrapper(*args, **kwargs):
            last_exc = None
            for attempt in range(max_retries + 1):
                try:
                    return await func(*args, **kwargs)
                except Exception as exc:
                    if not is_retryable_lock_error(exc) or attempt == max_retries:
                        raise
                    last_exc = exc
                    delay = base_delay * (2 ** attempt)
                    logger.warning(
                        "db_lock_retry_async: attempt %d/%d, sleeping %.1f s — %s",
                        attempt + 1,
                        max_retries,
                        delay,
                        str(exc),
                    )
                    await asyncio.sleep(delay)
            raise last_exc  # unreachable; satisfies type-checkers
        return wrapper
    return decorator
