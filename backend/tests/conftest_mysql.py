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
RESOLVED 2026-08-17 — THE SCHEMA WAS NEVER BROKEN; THE CONTAINER WAS WRONG
-----------------------------------------------------------------------------
This file previously carried a "SCHEMA CAVEAT" saying that neither
``alembic upgrade head`` nor ``Base.metadata.create_all()`` could build the schema,
because both failed on ``iocs`` with::

    (1170, "BLOB/TEXT column 'value' used in key specification without a key length")

and concluded there was "no working path in this repository to create a fresh
database". **That conclusion was wrong, and its stated reason — "MySQL and MariaDB
both refuse to index a TEXT column without a prefix length" — was factually wrong
about MariaDB.**

Production is **MariaDB 11.8.8**, confirmed by the owner. On MariaDB 11.8:

* ``alembic upgrade head`` runs the entire chain clean, all six revisions.
* Unadapted ``Base.metadata.create_all()`` succeeds.
* The resulting ``uq_ioc_type_value`` spans the FULL ``(type, value)`` with
  ``SUB_PART NULL`` — byte-for-byte what production has.

Error 1170 is a MySQL-8-only restriction. The tier had been running against
``mysql:8.0`` since Spec 4, so **it was validating the wrong dialect**, and the
prefix-length workaround existed only to paper over that. Both are now gone:
``DB_IMAGE`` defaults to ``mariadb:11.8`` and this module creates the real schema.

Why it matters beyond tidiness — the workaround was not behaviour-neutral. Under a
``(type, value(700))`` prefix index, InnoDB locks a *different* key space than under
the full index, and the lock-contention conclusions in
``test_mysql_integration.py::TestCreateIocHoldsAWriteLockThroughEnrichment`` were
originally measured against the prefix version. Re-measured on MariaDB with the real
index, the conclusion held — but only after a second confound was ruled out (see that
test: on a near-empty table InnoDB gap-locks the whole range, so the result depends on
the table being populated). A schema workaround silently changed what a lock test was
measuring, which is the general hazard worth remembering.
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
    """The real metadata, unaltered.

    This used to rewrite ``uq_ioc_type_value`` into a ``(type, value(700))`` prefix
    index so MySQL 8 would accept it. That adaptation is **deleted**: MariaDB 11.8 —
    which is what production runs — creates the full-column index without complaint,
    so the tier now builds exactly the production schema. See the module docstring.

    Kept as a function rather than inlined because the fixtures below call it and a
    future divergence (if one is ever genuinely needed) should have one place to live.
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
