"""The password-throttle reservation under REAL concurrency (issue #127).

The in-memory tests run the compare-and-swap one call at a time. What they cannot
show is the thing the CAS exists for: many connections that have all read
``failed_login_attempts = 0`` racing to reserve, with InnoDB row locks deciding the
order. Without the equality in the WHERE every one of them would be evaluated. With
it, the first UPDATE wins, the others block on its row lock, re-read the committed
row (an UPDATE is a current read, not a snapshot), match zero rows, and are refused
without their password ever being checked.

Opt-in tier: ``docker compose up -d db`` then ``python -m pytest -m mysql``.
"""

import asyncio
from datetime import datetime

import pytest
import sqlalchemy as sa
from passlib.context import CryptContext

from app.models.user import User
from app.services.password_throttle import verify_password_throttled

pytestmark = pytest.mark.mysql

PARALLEL = 20


class CountingContext:
    """Wraps a CryptContext and counts REAL verifications vs. timing-only dummies."""

    def __init__(self):
        self._ctx = CryptContext(schemes=["bcrypt"], bcrypt__rounds=4)
        self.verified = 0
        self.dummies = 0

    def hash(self, password):
        return self._ctx.hash(password)

    def verify(self, password, hashed):
        self.verified += 1
        return self._ctx.verify(password, hashed)

    def dummy_verify(self):
        self.dummies += 1
        return self._ctx.dummy_verify()


@pytest.mark.asyncio
async def test_parallel_readers_of_the_same_count_get_one_guess(mysql_engine, mysql_async_url):
    from sqlalchemy.ext.asyncio import async_sessionmaker, create_async_engine

    ctx = CountingContext()
    with mysql_engine.begin() as conn:
        conn.execute(sa.text("SET FOREIGN_KEY_CHECKS=0"))
        conn.execute(sa.text("TRUNCATE TABLE users"))
        conn.execute(sa.text("SET FOREIGN_KEY_CHECKS=1"))
        conn.execute(sa.insert(User.__table__).values(
            id="race-user", username="race", email="race@example.com",
            hashed_password=ctx.hash("right-password"), role="viewer", is_active=True,
            created_at=datetime(2026, 1, 1), failed_login_attempts=0,
        ))

    engine = create_async_engine(mysql_async_url, pool_size=PARALLEL, max_overflow=0)
    Session = async_sessionmaker(engine, expire_on_commit=False)
    everyone_has_read = asyncio.Barrier(PARALLEL)

    async def attempt():
        async with Session() as db:
            user = (await db.execute(sa.select(User).where(User.id == "race-user"))).scalar_one()
            assert user.failed_login_attempts == 0
            await everyone_has_read.wait()  # nobody writes until all have the stale count
            ok = await verify_password_throttled(db, user, "wrong-password", ctx)
            await db.commit()
            return ok

    try:
        results = await asyncio.gather(*(attempt() for _ in range(PARALLEL)))
    finally:
        await engine.dispose()

    with mysql_engine.connect() as conn:
        stored = conn.execute(sa.text(
            "SELECT failed_login_attempts FROM users WHERE id = 'race-user'"
        )).scalar()

    assert results == [False] * PARALLEL
    assert ctx.verified == 1, f"{ctx.verified} passwords were checked from one stale count"
    assert ctx.dummies == PARALLEL - 1, "refused attempts must still spend a hash"
    assert stored == 1
