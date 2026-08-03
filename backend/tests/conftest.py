"""Shared test fixtures.

The environment is populated **before** ``app`` is imported: ``app.config``
requires DATABASE_URL and refuses placeholder SECRET_KEY values, so importing a
module first would fail at collection time.

No test touches a real database. Endpoint tests override the ``get_db``
dependency with an in-memory stub, which is sufficient because authorization is
resolved before any handler body runs.
"""

import os

os.environ.setdefault("DATABASE_URL", "mysql+pymysql://test:test@localhost/test_db")
os.environ.setdefault("SECRET_KEY", "t3st-secret-key-that-is-long-enough-to-pass-validation")
os.environ.setdefault("ENVIRONMENT", "development")
os.environ.setdefault("ENABLE_ERROR_EMAILS", "false")
os.environ.setdefault("CORS_ORIGINS", "http://localhost:3000")

from datetime import datetime  # noqa: E402

import pytest  # noqa: E402
from fastapi.testclient import TestClient  # noqa: E402

from app.api import deps  # noqa: E402
from app.database import get_db  # noqa: E402
from app.main import app  # noqa: E402
from app.models.user import User  # noqa: E402


class FakeResult:
    """Mimics the subset of SQLAlchemy's Result API the handlers use."""

    def __init__(self, obj=None):
        self._obj = obj

    def scalar_one_or_none(self):
        return self._obj

    def scalar_one(self):
        return self._obj

    def scalar(self):
        return self._obj

    def scalars(self):
        return self

    def first(self):
        return self._obj

    def all(self):
        return [self._obj] if self._obj is not None else []

    def fetchall(self):
        return self.all()

    def one(self):
        return self._obj


class FakeSession:
    """Async session stub: every query returns the same configured object."""

    def __init__(self, obj=None):
        self.obj = obj
        self.added = []

    async def execute(self, *args, **kwargs):
        return FakeResult(self.obj)

    async def commit(self):
        pass

    async def rollback(self):
        pass

    async def flush(self):
        pass

    async def refresh(self, *args, **kwargs):
        pass

    async def delete(self, *args, **kwargs):
        pass

    def add(self, obj):
        self.added.append(obj)


def make_user(role: str = "viewer", is_active: bool = True, user_id: str = "user-1") -> User:
    """Build a User that satisfies UserResponse validation without a database."""
    return User(
        id=user_id,
        username="tester",
        email="tester@example.com",
        hashed_password="not-a-real-hash",
        full_name="Test User",
        role=role,
        is_active=is_active,
        created_at=datetime(2026, 1, 1),
    )


@pytest.fixture
def client():
    """TestClient with dependency overrides cleared between tests."""
    with TestClient(app, raise_server_exceptions=False) as c:
        yield c
    app.dependency_overrides.clear()


@pytest.fixture
def as_role(client):
    """Authenticate the client as a given role and stub the database.

    Returns a callable: ``as_role("admin") -> {"Authorization": "Bearer ..."}``
    """

    def _apply(role: str, is_active: bool = True, db_obj=None):
        user = make_user(role=role, is_active=is_active)

        async def _override():
            yield FakeSession(db_obj if db_obj is not None else user)

        app.dependency_overrides[get_db] = _override
        return {"Authorization": f"Bearer {deps.create_access_token(user)}"}

    return _apply


# ── Opt-in MySQL tier + statement counter ────────────────────────────────────
# Fixtures live in conftest_mysql.py; re-exported here so pytest discovers them.
# None of this runs during the default `python -m pytest`, which stays
# database-free at ~5s via `-m "not mysql"` in pytest.ini.
from tests.conftest_mysql import (  # noqa: E402,F401
    StatementCounter,
    attach_counter,
    detach_counter,
    mysql_async_url,
    mysql_engine,
    mysql_server_info,
    mysql_session,
    mysql_test_url,
    statement_counter,
)
