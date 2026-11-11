"""Per-account password back-off (issue #127).

Every gate that checks a user's OWN password goes through
:func:`verify_password_throttled`: login, change-password, the email-change request,
and an admin confirming their identity to change someone else's email. One counter
for all of them — otherwise the token-authenticated gates are an unthrottled oracle
around the login one.

Rules (all pinned by tests/test_login_throttle.py):

* **Escalating, capped back-off, never a hard lock.** A hard lock on a known admin
  email is a denial-of-service primitive. The first ``LOGIN_FREE_ATTEMPTS - 1`` wrong
  passwords cost nothing; after that each attempt locks the account for
  ``BASE * 2^k`` seconds up to ``MAX``.
* **The caller returns the same response either way.** This function only says
  True/False; it never tells the caller *why*. A throttled attempt still spends a
  bcrypt verification (``dummy_verify``) so latency does not distinguish "locked"
  from "wrong password".
* **Keyed to the account, never to the source address.** This module has no access
  to the HTTP layer at all.
* **Attempts are reserved, not counted afterwards.** A plain read-check-increment lets
  N parallel attempts all read the same count and all be evaluated. Instead each
  attempt first claims a slot with a compare-and-swap ``UPDATE ... WHERE
  failed_login_attempts = <seen> AND (not locked)``; a request whose read is stale
  matches zero rows and is refused without evaluating the password.
* **The reservation is COMMITTED before the verdict.** ``get_db`` rolls back when the
  handler raises, and every failure path here ends in a 401/400 — an uncommitted
  increment would be rolled back with it, and the counter would never move. This is
  a deliberate exception to the flush-not-commit rule, like ``_consume_otp``'s.
* **A refused attempt writes nothing,** so hammering a locked account does not extend
  its lock beyond the schedule.
"""

from datetime import datetime, timedelta, timezone

import structlog
from passlib.context import CryptContext
from sqlalchemy import update
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm.attributes import set_committed_value

from app.config import settings
from app.models.user import User

logger = structlog.get_logger()


def _naive_utcnow() -> datetime:
    return datetime.now(timezone.utc).replace(tzinfo=None)


def backoff_seconds(attempt_number: int) -> int:
    """Lock length after the ``attempt_number``-th consecutive failure (1-based)."""
    free = settings.LOGIN_FREE_ATTEMPTS
    if attempt_number < free:
        return 0
    exponent = min(attempt_number - free, 32)  # bounded: no huge ints on an abused account
    return min(settings.LOGIN_BACKOFF_BASE_SECONDS * (2 ** exponent),
               settings.LOGIN_BACKOFF_MAX_SECONDS)


async def verify_password_throttled(
    db: AsyncSession, user: User, password: str, pwd_context: CryptContext
) -> bool:
    """True only if the account may attempt now AND ``password`` is correct."""
    now = _naive_utcnow()
    seen_attempts = user.failed_login_attempts or 0
    seen_lock = user.locked_until

    if seen_lock is not None and seen_lock > now:
        pwd_context.dummy_verify()
        logger.info("password_attempt_throttled", user_id=str(user.id))
        return False

    attempt = seen_attempts + 1
    wait = backoff_seconds(attempt)
    new_lock = now + timedelta(seconds=wait) if wait else None

    # End the caller's (read-only, so far) transaction BEFORE the reservation.
    # MariaDB >= 11.6 defaults innodb_snapshot_isolation=ON: an UPDATE of a row this
    # transaction already READ, after another connection changed it, raises 1020
    # "Record has changed since last read" instead of matching zero rows - so a
    # parallel loser would get a 500 rather than the uniform refusal. A fresh
    # transaction whose first statement is the UPDATE has no read view, waits on the
    # winner's row lock, re-reads the committed row and simply matches nothing.
    # Pinned by tests/test_login_throttle_mysql.py. Callers must not have written
    # anything they would not want committed at this point; all four call sites have
    # only read.
    await db.commit()

    reserved = await db.execute(
        update(User)
        .where(
            User.id == user.id,
            User.failed_login_attempts == seen_attempts,
            (User.locked_until.is_(None)) | (User.locked_until <= now),
        )
        .values(failed_login_attempts=attempt, locked_until=new_lock)
        .execution_options(synchronize_session=False)
    )
    if reserved.rowcount != 1:
        # Another attempt claimed this slot between our read and our write.
        pwd_context.dummy_verify()
        logger.info("password_attempt_lost_race", user_id=str(user.id))
        return False
    await db.commit()
    set_committed_value(user, "failed_login_attempts", attempt)
    set_committed_value(user, "locked_until", new_lock)

    if not pwd_context.verify(password, user.hashed_password):
        if new_lock is not None:
            logger.info("password_backoff_started", user_id=str(user.id),
                        attempts=attempt, lock_seconds=wait)
        return False

    await db.execute(
        update(User)
        .where(User.id == user.id)
        .values(failed_login_attempts=0, locked_until=None)
        .execution_options(synchronize_session=False)
    )
    set_committed_value(user, "failed_login_attempts", 0)
    set_committed_value(user, "locked_until", None)
    return True
