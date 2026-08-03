"""Statement-count ceilings for the endpoints known to issue N+1 queries.

    docker compose up -d db
    python -m pytest -m mysql

WHY COUNT STATEMENTS RATHER THAN MEASURE TIME. Local latency to a container is
~0.1 ms. Render to Hostinger is 50-300 ms, and Render has no India region, so a
round-trip count that is invisible locally dominates production wall-clock
entirely. 300 queries × 0.1 ms = 30 ms and looks instant; the same 300 × 150 ms is
45 seconds and times out. Counting statements is latency-independent, stable in CI
and immune to a loaded developer machine.

WHY SEVERAL OF THESE ARE xfail(strict=True). The ceilings describe the intended
post-fix behaviour, and the fixes are not in this change set. `strict=True` means:

  * while the N+1 remains, the test reports XFAIL — visibly expected, not a
    failure, and not something a reader mistakes for a broken suite;
  * the moment someone fixes the endpoint, it reports XPASS and **fails the run**,
    which is the prompt to delete the marker and lock the ceiling in.

That is the property a plain `skip` would not give: a skip stays silent forever and
the ceiling never becomes real. Each marker names the work that retires it.
"""

from __future__ import annotations

import uuid
from datetime import datetime, timedelta, timezone

import pytest
import sqlalchemy as sa

from tests.conftest_mysql import attach_counter, detach_counter, mysql_test_url

pytestmark = [pytest.mark.mysql, pytest.mark.query_budget]

TECHNIQUE_COUNT = 40
IOC_COUNT = 60


def _naive_utc() -> datetime:
    return datetime.now(timezone.utc).replace(tzinfo=None)


@pytest.fixture
def seeded(mysql_session):
    """A corpus large enough that an N+1 is unambiguous.

    40 techniques and 60 IOCs: a per-technique COUNT shows up as 40+ statements,
    which no reasonable implementation would need.
    """
    from app.models.attack_technique import AttackTechnique
    from app.models.ioc import IOC

    tactics = ["initial-access", "execution", "persistence", "defense-evasion"]
    for i in range(TECHNIQUE_COUNT):
        mysql_session.add(AttackTechnique(
            id=f"T{1000 + i}",
            name=f"Technique {i}",
            tactic=tactics[i % len(tactics)],
            description="seeded",
            url=f"https://attack.mitre.org/techniques/T{1000 + i}/",
            data_sources=[],
        ))

    for i in range(IOC_COUNT):
        mysql_session.add(IOC(
            id=str(uuid.uuid4()),
            type=["ip", "domain", "url", "hash"][i % 4],
            value=f"seed-{i}.example",
            threat_score=(i * 7) % 101,
            confidence=50,
            first_seen=_naive_utc() - timedelta(days=i % 30),
            last_seen=_naive_utc() - timedelta(days=i % 30),
            sighting_count=1 + (i % 5),
            tags=["seeded"],
            metadata_={},
            mitre_techniques=[f"T{1000 + (i % TECHNIQUE_COUNT)}"],
            created_at=_naive_utc() - timedelta(days=i % 30),
            updated_at=_naive_utc(),
        ))
    mysql_session.commit()
    return {"techniques": TECHNIQUE_COUNT, "iocs": IOC_COUNT}


@pytest.fixture
def counted_client(seeded):
    """TestClient wired to the real MySQL container, with a statement counter.

    Returns ``(client, headers, counter)``. Authentication is stubbed at the
    dependency level — this measures query shape, not authorization, which
    tests/test_access_control.py already covers.
    """
    from fastapi.testclient import TestClient
    from sqlalchemy.ext.asyncio import async_sessionmaker, create_async_engine

    from app.api import deps
    from app.database import get_db
    from app.main import app
    from tests.conftest import make_user

    async_engine = create_async_engine(
        mysql_test_url().replace("mysql+pymysql://", "mysql+aiomysql://"),
        pool_pre_ping=True,
    )
    Session = async_sessionmaker(async_engine, expire_on_commit=False)
    counter = attach_counter(async_engine.sync_engine)

    async def _override_db():
        async with Session() as session:
            yield session

    user = make_user(role="admin")

    async def _override_user():
        return user

    app.dependency_overrides[get_db] = _override_db
    app.dependency_overrides[deps.get_current_user] = _override_user

    with TestClient(app) as client:
        headers = {"Authorization": f"Bearer {deps.create_access_token(user)}"}
        yield client, headers, counter

    app.dependency_overrides.clear()
    detach_counter(counter)
    # Dispose through the async API. Letting the sync engine drop aiomysql
    # connections leaves them to __del__ after the loop has closed, which surfaces
    # as "RuntimeError: Event loop is closed" in a PytestUnraisableExceptionWarning
    # — noise that looks like a real defect.
    import asyncio

    asyncio.run(async_engine.dispose())


def _measure(counted_client, path):
    client, headers, counter = counted_client
    counter.reset()
    response = client.get(path, headers=headers)
    return response, counter


class TestAttackEndpointBudgets:
    @pytest.mark.xfail(
        strict=True,
        reason="N+1: attack.py::get_attack_matrix issues one COUNT per technique. "
               "Retire this marker when it becomes a single GROUP BY.",
    )
    def test_attack_matrix_stays_under_five_statements(self, counted_client):
        response, counter = _measure(counted_client, "/api/v1/attack/matrix")
        assert response.status_code == 200, response.text
        assert counter.count <= 5, f"\n{counter.summary()}"

    @pytest.mark.xfail(
        strict=True,
        reason="N+1: attack.py::get_heatmap issues one COUNT per technique. "
               "Retire this marker when it becomes a single GROUP BY.",
    )
    def test_attack_heatmap_stays_under_five_statements(self, counted_client):
        response, counter = _measure(counted_client, "/api/v1/attack/heatmap")
        assert response.status_code == 200, response.text
        assert counter.count <= 5, f"\n{counter.summary()}"


class TestDashboardEndpointBudgets:
    @pytest.mark.xfail(
        strict=True,
        reason="N+1: dashboard.py::get_trends issues 2 queries per day requested, "
               "so days=30 is ~60. Retire when it becomes one GROUP BY over a date "
               "expression.",
    )
    def test_trends_30_days_stays_under_five_statements(self, counted_client):
        response, counter = _measure(
            counted_client, "/api/v1/dashboard/trends?days=30"
        )
        assert response.status_code == 200, response.text
        assert counter.count <= 5, f"\n{counter.summary()}"

    def test_stats_stays_under_ten_statements(self, counted_client):
        """Not xfail — `stats` is aggregate-shaped already and should pass today.

        Kept as a live ceiling so a future edit cannot quietly turn it into a loop.
        """
        response, counter = _measure(counted_client, "/api/v1/dashboard/stats")
        assert response.status_code == 200, response.text
        assert counter.count <= 10, f"\n{counter.summary()}"


class TestBudgetHarnessItself:
    """The guard is only worth having if it would actually catch a regression."""

    def test_the_counter_scales_with_the_corpus(self, counted_client, seeded):
        """Proves the N+1 is real rather than a constant overhead.

        The matrix endpoint's statement count must track the number of techniques,
        which is what distinguishes an N+1 from a fixed set-up cost.
        """
        response, counter = _measure(counted_client, "/api/v1/attack/matrix")
        assert response.status_code == 200
        assert counter.count >= seeded["techniques"], (
            "expected at least one statement per technique from the known N+1; "
            f"got {counter.count} for {seeded['techniques']} techniques"
        )

    def test_counted_endpoints_actually_return_data(self, counted_client):
        """A ceiling met by returning nothing is not a passing ceiling."""
        client, headers, _ = counted_client
        matrix = client.get("/api/v1/attack/matrix", headers=headers)
        assert matrix.status_code == 200
        assert matrix.json(), "matrix returned an empty payload"

    def test_the_counter_records_executemany_as_one_statement(self, mysql_engine):
        """The property the ingestion path was tuned around."""
        from app.models.ioc import IOC

        counter = attach_counter(mysql_engine)
        try:
            table = IOC.__table__
            with mysql_engine.begin() as conn:
                conn.execute(
                    table.insert(),
                    [
                        {
                            "id": str(uuid.uuid4()), "type": "domain",
                            "value": f"em-{i}.example", "threat_score": 1,
                            "confidence": 1, "first_seen": _naive_utc(),
                            "last_seen": _naive_utc(), "sighting_count": 1,
                            "tags": [], "metadata": {}, "mitre_techniques": [],
                            "created_at": _naive_utc(), "updated_at": _naive_utc(),
                        }
                        for i in range(25)
                    ],
                )
            inserts = counter.matching("insert into iocs")
            assert len(inserts) == 1, counter.summary()
        finally:
            detach_counter(counter)
            with mysql_engine.begin() as conn:
                conn.execute(sa.text("DELETE FROM iocs WHERE value LIKE 'em-%'"))
