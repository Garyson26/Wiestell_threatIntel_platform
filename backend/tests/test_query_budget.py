"""Statement-count ceilings for the endpoints known to issue N+1 queries.

    docker compose up -d db
    python -m pytest -m mysql

WHY COUNT STATEMENTS RATHER THAN MEASURE TIME. Local latency to a container is
~0.1 ms. Render to Hostinger is 50-300 ms, and Render has no India region, so a
round-trip count that is invisible locally dominates production wall-clock
entirely. 300 queries × 0.1 ms = 30 ms and looks instant; the same 300 × 150 ms is
45 seconds and times out. Counting statements is latency-independent, stable in CI
and immune to a loaded developer machine.

THE xfail(strict=True) MARKERS ARE GONE, AND THAT WAS THE POINT. Three ceilings
described intended post-fix behaviour while the N+1s were still live. `strict=True`
meant the tests reported XFAIL — visibly expected, not mistaken for a broken suite —
and the moment the endpoints were fixed they reported XPASS and **failed the run**,
which is what prompted retiring the markers and locking the ceilings in. A plain
`skip` would have stayed silent forever and the ceilings would never have become real.

All three were retired on 2026-07-31 when Phase 5 landed the rewrites. Measured:

  | Endpoint | Before | After |
  |---|---|---|
  | `/attack/matrix`            | 41 | 2 |
  | `/attack/heatmap`           | 41 | 2 |
  | `/dashboard/trends?days=30` | 60 | 3 |
  | `/dashboard/stats`          |  3 | 3 (already aggregate-shaped) |

The counts are now flat in the corpus and in `days` rather than proportional, which is
the property worth guarding — `days` reaches 90 and the technique catalogue reaches the
hundreds. Every ceiling below is a live assertion, so a reintroduced loop fails at once.
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
    # Markers retired 2026-07-31: both endpoints now take one catalogue query plus one
    # aggregate scan. Measured 41 -> 2 statements each. The ceilings below are live
    # assertions rather than aspirations, so a reintroduced loop fails immediately.
    def test_attack_matrix_stays_under_five_statements(self, counted_client):
        response, counter = _measure(counted_client, "/api/v1/attack/matrix")
        assert response.status_code == 200, response.text
        assert counter.count <= 5, f"\n{counter.summary()}"

    def test_attack_heatmap_stays_under_five_statements(self, counted_client):
        response, counter = _measure(counted_client, "/api/v1/attack/heatmap")
        assert response.status_code == 200, response.text
        assert counter.count <= 5, f"\n{counter.summary()}"


class TestDashboardEndpointBudgets:
    # Marker retired 2026-07-31: one GROUP BY over func.DATE with a conditional sum for
    # the critical count. Measured 60 -> 3 statements at days=30, and now flat in `days`
    # rather than 2n — the property worth having, since days can reach 90.
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

    def test_the_matrix_count_no_longer_scales_with_the_corpus(
        self, counted_client, seeded
    ):
        """The property the Phase 5 rewrite buys, stated as an inequality.

        This asserted the *opposite* until 2026-07-31 — that the count tracked the
        technique total — as proof the N+1 was real rather than a fixed set-up cost. The
        N+1 is gone, so the assertion inverts: the statement count must be well below the
        technique count, which is what "constant rather than proportional" means when the
        catalogue is the thing that used to drive it.
        """
        response, counter = _measure(counted_client, "/api/v1/attack/matrix")
        assert response.status_code == 200
        assert counter.count < seeded["techniques"], (
            f"{counter.count} statements for {seeded['techniques']} techniques - the "
            "count is tracking the catalogue again, so the N+1 has returned\n"
            + counter.summary()
        )

    def test_the_counter_detects_a_deliberate_n_plus_one(self, mysql_engine):
        """Proves the counter is still sensitive, without needing a live bug.

        The sensitivity check used to ride on the matrix endpoint's N+1, so fixing that
        endpoint removed the harness's own evidence that it can detect one. A guard that
        cannot be shown to fire is indistinguishable from a guard that does not work —
        the standing rule in CLAUDE.md — so the loop is constructed here instead.
        """
        from sqlalchemy import func, select

        from app.models.attack_technique import AttackTechnique

        counter = attach_counter(mysql_engine)
        try:
            with mysql_engine.connect() as conn:
                for _ in range(7):
                    conn.execute(select(func.count(AttackTechnique.id)))
        finally:
            detach_counter(counter)
        assert counter.count == 7, (
            f"the counter saw {counter.count} of 7 deliberate statements, so the "
            "ceilings above cannot be trusted\n" + counter.summary()
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
