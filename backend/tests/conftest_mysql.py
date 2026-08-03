"""Fixtures for the opt-in ``-m mysql`` tier, plus the statement counter.

Imported by ``tests/conftest.py`` so the fixtures are session-wide. Kept in its own
module because none of it is used by the default database-free run.

Run the tier with::

    docker compose up -d db
    python -m pytest -m mysql

The tier is skipped, with a reason naming the command above, whenever the
container is unreachable — a developer without Docker still gets a green default
suite.

-----------------------------------------------------------------------------
SCHEMA CAVEAT — READ BEFORE TRUSTING THESE TESTS
-----------------------------------------------------------------------------
Neither ``alembic upgrade head`` nor ``Base.metadata.create_all()`` can build this
schema on MySQL 8. Both fail on the ``iocs`` table with::

    (1170, "BLOB/TEXT column 'value' used in key specification without a key length")

because ``iocs.value`` is ``TEXT`` and carries ``UNIQUE(type, value)``; MySQL and
MariaDB both refuse to index a TEXT column without a prefix length. Found
2026-07-30. It means there is **no working path in this repository to create a
fresh database**, and production's schema must therefore have been built by some
other route or predate the column's current type.

Resolving that needs `SHOW CREATE TABLE iocs;` against production and an owner
decision, so it is deliberately NOT fixed here. To make the tier functional now,
:func:`_test_metadata` applies a **test-only** prefix-length adaptation to that one
constraint. Consequences to keep in mind:

* Everything else — column types, JSON columns, datetime handling, the ingestion
  statements, savepoints — is the real schema and the real code path.
* Uniqueness in the test schema is on ``(type, value(700))`` rather than the full
  value, so two values sharing a 700-character prefix would collide here and not
  in production. No test depends on that distinction. 700 rather than 768 because
  InnoDB caps a key at 3072 bytes and utf8mb4 costs 4 bytes per character, which
  the ``type`` column also draws on: 768*4 + 80 exceeds the cap (error 1071).
* **Delete this adaptation** once the model is fixed. It is a scaffold, not a
  design.
"""

from __future__ import annotations

import os
import time
from typing import List

import pytest
import sqlalchemy as sa
from sqlalchemy import event

# Default matches docker-compose.yml's db service (loopback, port 3307, root user
# so the tier can CREATE/DROP freely). Override with MYSQL_TEST_URL.
DEFAULT_MYSQL_TEST_URL = "mysql+pymysql://root:sentinel@127.0.0.1:3307/sentinel_test"

SKIP_REASON = (
    "MySQL test container unreachable. Start it with:  docker compose up -d db  "
    "(or set MYSQL_TEST_URL). See tests/conftest_mysql.py."
)


def mysql_test_url() -> str:
    return os.environ.get("MYSQL_TEST_URL", DEFAULT_MYSQL_TEST_URL)


# ── Statement counter (B.4) ──────────────────────────────────────────────────


class StatementCounter:
    """Counts SQL statements issued on an engine.

    Latency-independent by design. Local latency to a container is ~0.1 ms while
    Render→Hostinger is 50-300 ms with no India region, so an N+1 endpoint looks
    instant locally and is unusable in production. Simulating latency is fragile
    and CI-hostile; counting statements is neither.

    ``executemany`` counts as one statement, which matches how the driver sends it
    and is the property the ingestion path was tuned around.
    """

    def __init__(self) -> None:
        self.statements: List[str] = []

    # -- context manager ----------------------------------------------------
    def __enter__(self) -> "StatementCounter":
        return self

    def __exit__(self, *exc) -> None:
        return None

    @property
    def count(self) -> int:
        return len(self.statements)

    def record(self, sql: str) -> None:
        self.statements.append(" ".join(str(sql).split()))

    def reset(self) -> None:
        self.statements.clear()

    def matching(self, needle: str) -> List[str]:
        return [s for s in self.statements if needle.lower() in s.lower()]

    def summary(self, limit: int = 40) -> str:
        """Grouped report — the useful thing to print when a ceiling fails."""
        from collections import Counter

        shapes = Counter(s[:90] for s in self.statements)
        lines = [f"{self.count} statements:"]
        for shape, n in shapes.most_common(limit):
            lines.append(f"  {n:4d}x  {shape}")
        return "\n".join(lines)


def attach_counter(engine) -> StatementCounter:
    """Attach a ``before_cursor_execute`` listener and return its counter."""
    counter = StatementCounter()

    @event.listens_for(engine, "before_cursor_execute")
    def _before(conn, cursor, statement, parameters, context, executemany):  # noqa: ANN001
        counter.record(statement)

    counter._listener = _before  # type: ignore[attr-defined]
    counter._engine = engine     # type: ignore[attr-defined]
    return counter


def detach_counter(counter: StatementCounter) -> None:
    engine = getattr(counter, "_engine", None)
    listener = getattr(counter, "_listener", None)
    if engine is not None and listener is not None:
        try:
            event.remove(engine, "before_cursor_execute", listener)
        except Exception:
            pass


@pytest.fixture
def statement_counter():
    """Counter factory usable without a database.

    ``counter = statement_counter(engine)`` attaches to any engine, sync or async
    (pass ``engine.sync_engine`` for async ones), and detaches at teardown.
    """
    created: List[StatementCounter] = []

    def _make(engine) -> StatementCounter:
        target = getattr(engine, "sync_engine", engine)
        counter = attach_counter(target)
        created.append(counter)
        return counter

    yield _make
    for counter in created:
        detach_counter(counter)


# ── Schema (see the caveat in the module docstring) ──────────────────────────


def _test_metadata() -> sa.MetaData:
    """A copy of the real metadata that MySQL will actually accept.

    Only the ``uq_ioc_type_value`` constraint is altered, and only because
    ``iocs.value`` is TEXT. See the module docstring.
    """
    from app.database import Base
    # Import for the side effect of registering every table on Base.metadata.
    import app.models.attack_technique  # noqa: F401
    import app.models.enrichment  # noqa: F401
    import app.models.feed  # noqa: F401
    import app.models.ioc  # noqa: F401
    import app.models.ioc_relationship  # noqa: F401
    import app.models.ioc_source  # noqa: F401
    import app.models.otp  # noqa: F401
    import app.models.report  # noqa: F401
    import app.models.user  # noqa: F401

    metadata = sa.MetaData()
    for table in Base.metadata.tables.values():
        table.to_metadata(metadata)

    iocs = metadata.tables["iocs"]
    for constraint in list(iocs.constraints):
        if constraint.name == "uq_ioc_type_value":
            iocs.constraints.discard(constraint)
    # Prefix-length unique index — the MySQL-legal equivalent.
    already = any(ix.name == "uq_ioc_type_value" for ix in iocs.indexes)
    if not already:
        sa.Index(
            "uq_ioc_type_value",
            iocs.c.type,
            iocs.c.value,
            unique=True,
            mysql_length={"value": 700},
        )
    return metadata


@pytest.fixture(scope="session")
def mysql_engine():
    """Session-scoped sync engine against the container; skips if unreachable."""
    url = mysql_test_url()
    try:
        engine = sa.create_engine(url, pool_pre_ping=True, future=True)
        with engine.connect() as conn:
            conn.execute(sa.text("SELECT 1"))
    except Exception as exc:  # noqa: BLE001
        pytest.skip(f"{SKIP_REASON} ({type(exc).__name__}: {str(exc)[:80]})")

    metadata = _test_metadata()
    metadata.drop_all(bind=engine)
    metadata.create_all(bind=engine)
    yield engine
    metadata.drop_all(bind=engine)
    engine.dispose()


@pytest.fixture
def mysql_session(mysql_engine):
    """Fresh session per test, with every table truncated first."""
    from sqlalchemy.orm import sessionmaker

    metadata = _test_metadata()
    with mysql_engine.begin() as conn:
        conn.execute(sa.text("SET FOREIGN_KEY_CHECKS=0"))
        for table in reversed(metadata.sorted_tables):
            conn.execute(sa.text(f"TRUNCATE TABLE `{table.name}`"))
        conn.execute(sa.text("SET FOREIGN_KEY_CHECKS=1"))

    Session = sessionmaker(bind=mysql_engine, future=True)
    session = Session()
    try:
        yield session
    finally:
        session.rollback()
        session.close()


@pytest.fixture
def mysql_server_info(mysql_engine):
    """`(version_string, is_mariadb, wait_timeout)` for the container."""
    with mysql_engine.connect() as conn:
        version = conn.execute(sa.text("SELECT VERSION()")).scalar() or ""
        wait_timeout = conn.execute(sa.text("SELECT @@wait_timeout")).scalar()
    return version, "mariadb" in version.lower(), int(wait_timeout or 0)


@pytest.fixture
def mysql_async_url() -> str:
    return mysql_test_url().replace("mysql+pymysql://", "mysql+aiomysql://")


def sleep_past_wait_timeout(wait_timeout: int, margin: float = 2.0) -> None:
    """Idle long enough for the server to drop the connection."""
    time.sleep(min(wait_timeout, 30) + margin)
