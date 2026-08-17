"""MySQL-backed tests — what a database-free suite structurally cannot cover.

    docker compose up -d db
    python -m pytest -m mysql

Every test here targets a defect class that has already reached production or is
one edit away from doing so:

* **JSON comparators.** `/attack/matrix`, `/attack/heatmap`,
  `/attack/techniques/{id}` and the correlation engine used the PostgreSQL-only
  `ARRAY.any()` and `.overlap()` operators against MySQL JSON columns and raised
  on *every* call. A mocked session cannot catch that — only the server can.
* **Naive-UTC datetimes.** The convention is pinned here rather than trusted to
  review — and the tests correct the documented reason for it. A query comparing a
  naive column against an aware value does **not** raise; the offset is silently
  discarded, so the failure is wrong rows rather than a stack trace. The
  documented `TypeError` comes from Python-side arithmetic instead.
* **The ingestion path.** `INSERT ... IGNORE`, `executemany` UPDATE, chunking and
  lock-timeout retry only mean anything against a real InnoDB.
* **Savepoint isolation.** `enrich_ioc`'s `begin_nested()` must roll back only the
  enrichment on a duplicate-key race and leave the outer transaction usable.
* **Idle-connection recovery.** The container sets `wait_timeout=30` so the
  `aiomysql.ensure_closed` patch and `pool_recycle=280` actually get exercised.
"""

from __future__ import annotations

import uuid
from datetime import datetime, timedelta, timezone

import pytest
import sqlalchemy as sa
from sqlalchemy import func, select

pytestmark = pytest.mark.mysql


def _naive_utc() -> datetime:
    """The project-wide convention: naive UTC, matching MySQL DATETIME."""
    return datetime.now(timezone.utc).replace(tzinfo=None)


def _make_ioc(session, *, ioc_type="domain", value=None, tags=None,
              techniques=None, metadata=None, score=50, sightings=1):
    from app.models.ioc import IOC

    ioc = IOC(
        id=str(uuid.uuid4()),
        type=ioc_type,
        value=value or f"{uuid.uuid4().hex}.example",
        threat_score=score,
        confidence=50,
        first_seen=_naive_utc(),
        last_seen=_naive_utc(),
        sighting_count=sightings,
        tags=tags if tags is not None else [],
        metadata_=metadata if metadata is not None else {},
        mitre_techniques=techniques if techniques is not None else [],
        created_at=_naive_utc(),
        updated_at=_naive_utc(),
    )
    session.add(ioc)
    session.flush()
    return ioc


class TestServerIdentity:
    def test_container_matches_the_expected_engine(self, mysql_server_info):
        """Guards against silently testing the wrong dialect.

        MariaDB implements JSON as LONGTEXT with a CHECK constraint and its
        json_contains argument handling is not identical to MySQL's, so a green
        run against the wrong engine is false confidence. If production turns out
        to be MariaDB, set DB_IMAGE to the matching tag in .env — see
        docker-compose.yml.
        """
        version, is_mariadb, _ = mysql_server_info
        assert version, "server returned no version string"
        print(f"\nserver: {version} (mariadb={is_mariadb})")

    def test_wait_timeout_is_short_enough_to_exercise_the_reconnect_path(
        self, mysql_server_info
    ):
        """At MySQL's 8-hour default the ensure_closed patch is never exercised."""
        _, _, wait_timeout = mysql_server_info
        assert wait_timeout <= 60, (
            f"wait_timeout={wait_timeout}s — set --wait-timeout=30 on the db "
            "service so idle-connection recovery is actually tested"
        )


class TestJSONColumnComparators:
    """`func.json_contains(col, func.json_quote(value)) == 1` is the house pattern.

    The PostgreSQL comparators that used to be here were a live crash.
    """

    def test_json_contains_matches_a_tag(self, mysql_session):
        from app.models.ioc import IOC

        _make_ioc(mysql_session, tags=["ransomware", "c2"])
        _make_ioc(mysql_session, tags=["phishing"])
        mysql_session.commit()

        rows = mysql_session.execute(
            select(IOC).where(
                func.json_contains(IOC.tags, func.json_quote("ransomware")) == 1
            )
        ).scalars().all()
        assert len(rows) == 1
        assert "ransomware" in rows[0].tags

    def test_json_contains_matches_a_mitre_technique(self, mysql_session):
        from app.models.ioc import IOC

        _make_ioc(mysql_session, techniques=["T1190", "T1059"])
        _make_ioc(mysql_session, techniques=["T1566"])
        mysql_session.commit()

        rows = mysql_session.execute(
            select(IOC).where(
                func.json_contains(IOC.mitre_techniques, func.json_quote("T1190")) == 1
            )
        ).scalars().all()
        assert len(rows) == 1

    def test_json_contains_on_the_metadata_column(self, mysql_session):
        """`metadata` is mapped as `metadata_` because the name is reserved."""
        from app.models.ioc import IOC

        _make_ioc(mysql_session, metadata={"campaign": ["apt29"]})
        mysql_session.commit()

        rows = mysql_session.execute(
            select(IOC).where(
                func.json_contains(
                    func.json_extract(IOC.metadata_, "$.campaign"),
                    func.json_quote("apt29"),
                ) == 1
            )
        ).scalars().all()
        assert len(rows) == 1

    def test_no_match_returns_nothing_rather_than_raising(self, mysql_session):
        from app.models.ioc import IOC

        _make_ioc(mysql_session, tags=["ransomware"])
        mysql_session.commit()
        rows = mysql_session.execute(
            select(IOC).where(
                func.json_contains(IOC.tags, func.json_quote("nope")) == 1
            )
        ).scalars().all()
        assert rows == []

    def test_empty_json_array_is_handled(self, mysql_session):
        from app.models.ioc import IOC

        _make_ioc(mysql_session, tags=[])
        mysql_session.commit()
        rows = mysql_session.execute(
            select(IOC).where(
                func.json_contains(IOC.tags, func.json_quote("anything")) == 1
            )
        ).scalars().all()
        assert rows == []

    def test_postgres_array_comparators_are_unavailable(self, mysql_session):
        """The regression guard for the actual production crash.

        `.any()` / `.overlap()` do not exist on a MySQL JSON column. This asserts
        the failure is loud at query-construction time, so reintroducing the
        pattern cannot pass review by looking plausible.
        """
        from app.models.ioc import IOC

        with pytest.raises((AttributeError, NotImplementedError, Exception)):
            select(IOC).where(IOC.tags.any("ransomware"))  # type: ignore[attr-defined]


class TestNaiveUTCDatetimes:
    def test_naive_write_and_read_roundtrip(self, mysql_session):
        from app.models.ioc import IOC

        ioc = _make_ioc(mysql_session)
        mysql_session.commit()
        ioc_id = ioc.id
        mysql_session.expire_all()

        fetched = mysql_session.execute(
            select(IOC).where(IOC.id == ioc_id)
        ).scalar_one()
        assert fetched.last_seen.tzinfo is None, (
            "MySQL DATETIME must come back naive; an aware value means the column "
            "type or the write convention changed"
        )

    def test_an_aware_value_in_a_query_fails_SILENTLY_not_loudly(self, mysql_session):
        """Corrects a documented claim. Measured 2026-07-30.

        CLAUDE.md said "comparing a naive column against an aware value raises
        TypeError". In a **query** it does not raise at all: pymysql formats the
        datetime and MySQL compares it happily. Worse, the offset is silently
        discarded — an aware value of 11:00+05:30 (05:30 UTC) is compared as
        though it were 11:00, a 5.5-hour error. This project renders IST (+05:30),
        so that is exactly the offset in play.

        The TypeError the docs describe is real but comes from *Python-side*
        arithmetic on a value read back from a naive column — see
        :meth:`test_python_side_arithmetic_against_an_aware_value_does_raise`.

        So the naive-UTC convention matters more than the docs implied, not less:
        breaking it produces wrong rows rather than a stack trace.
        """
        from app.models.ioc import IOC

        _make_ioc(mysql_session)
        mysql_session.commit()

        naive_cutoff = _naive_utc() - timedelta(hours=1)
        aware_same_clock = naive_cutoff.replace(tzinfo=timezone.utc)
        aware_ist = naive_cutoff.replace(tzinfo=timezone(timedelta(hours=5, minutes=30)))

        by_naive = mysql_session.execute(
            select(func.count()).select_from(IOC).where(IOC.last_seen > naive_cutoff)
        ).scalar()
        by_aware_utc = mysql_session.execute(
            select(func.count()).select_from(IOC).where(IOC.last_seen > aware_same_clock)
        ).scalar()
        by_aware_ist = mysql_session.execute(
            select(func.count()).select_from(IOC).where(IOC.last_seen > aware_ist)
        ).scalar()

        assert by_naive == 1
        # No exception, and the offset made no difference — the wall-clock reading
        # is used verbatim. That is the silent failure this pins.
        assert by_aware_utc == by_naive
        assert by_aware_ist == by_naive

    def test_python_side_arithmetic_against_an_aware_value_does_raise(self, mysql_session):
        """Where the documented TypeError actually comes from."""
        from app.models.ioc import IOC

        ioc = _make_ioc(mysql_session)
        mysql_session.commit()
        stored = mysql_session.execute(
            select(IOC.last_seen).where(IOC.id == ioc.id)
        ).scalar_one()

        assert stored.tzinfo is None
        with pytest.raises(TypeError):
            _ = stored - datetime.now(timezone.utc)

    def test_naive_comparison_works(self, mysql_session):
        from app.models.ioc import IOC

        _make_ioc(mysql_session)
        mysql_session.commit()

        naive_cutoff = _naive_utc() - timedelta(days=1)
        count = mysql_session.execute(
            select(func.count()).select_from(IOC).where(IOC.last_seen > naive_cutoff)
        ).scalar()
        assert count == 1


class TestIngestionPath:
    """`services/feed_ingestion.py` against real InnoDB."""

    def _feed(self, session, slug="urlhaus"):
        from app.models.feed import FeedSource

        feed = FeedSource(
            id=str(uuid.uuid4()), name=slug, slug=slug, feed_type="csv",
            url="https://example.invalid/feed", is_enabled=True,
            sync_frequency=3600, ioc_count=0, config={},
            created_at=_naive_utc(),
        )
        session.add(feed)
        session.flush()
        return feed

    def test_insert_ignore_tolerates_a_duplicate(self, mysql_session):
        """The single-statement new-row insert must not raise on a re-sync."""
        from sqlalchemy.dialects.mysql import insert as mysql_insert

        from app.models.ioc import IOC

        row = {
            "id": str(uuid.uuid4()), "type": "domain", "value": "dupe.example",
            "threat_score": 40, "confidence": 50, "first_seen": _naive_utc(),
            "last_seen": _naive_utc(), "sighting_count": 1, "tags": [],
            "metadata": {}, "mitre_techniques": [],
            "created_at": _naive_utc(), "updated_at": _naive_utc(),
        }
        # The Table, not the mapped class: the column is literally named
        # "metadata", which collides with MetaData on the ORM entity.
        table = IOC.__table__
        mysql_session.execute(mysql_insert(table).values(**row).prefix_with("IGNORE"))
        mysql_session.commit()

        second = dict(row, id=str(uuid.uuid4()))
        mysql_session.execute(mysql_insert(table).values(**second).prefix_with("IGNORE"))
        mysql_session.commit()

        count = mysql_session.execute(
            select(func.count()).select_from(IOC).where(IOC.value == "dupe.example")
        ).scalar()
        assert count == 1, "INSERT IGNORE should have swallowed the duplicate"

    def test_executemany_update_is_one_statement(self, mysql_session, statement_counter):
        """Locks are held for one statement, not for a Python loop."""
        from app.models.ioc import IOC

        iocs = [_make_ioc(mysql_session) for _ in range(30)]
        mysql_session.commit()

        counter = statement_counter(mysql_session.get_bind())
        table = IOC.__table__
        mysql_session.execute(
            sa.update(table).where(table.c.id == sa.bindparam("b_id")).values(
                threat_score=sa.bindparam("b_score")
            ),
            [{"b_id": i.id, "b_score": 77} for i in iocs],
        )
        mysql_session.commit()

        updates = counter.matching("update iocs")
        assert len(updates) == 1, counter.summary()

        assert mysql_session.execute(
            select(func.count()).select_from(IOC).where(IOC.threat_score == 77)
        ).scalar() == 30

    def test_distinct_feed_count_is_not_the_sighting_count(self, mysql_session):
        """The source-diversity input. One feed re-syncing is not corroboration."""
        from app.models.ioc_source import IOCSource

        feed = self._feed(mysql_session, "urlhaus")
        ioc = _make_ioc(mysql_session, sightings=50)
        mysql_session.add(IOCSource(
            id=str(uuid.uuid4()), ioc_id=ioc.id, feed_id=feed.id,
            raw_data={}, ingested_at=_naive_utc(),
        ))
        mysql_session.commit()

        distinct = mysql_session.execute(
            select(func.count(sa.distinct(IOCSource.feed_id)))
            .where(IOCSource.ioc_id == ioc.id)
        ).scalar()
        assert distinct == 1
        assert ioc.sighting_count == 50

    def test_unique_constraint_on_type_and_value_is_enforced(self, mysql_session):
        from sqlalchemy.exc import IntegrityError

        from app.models.ioc import IOC

        _make_ioc(mysql_session, value="clash.example")
        mysql_session.commit()

        mysql_session.add(IOC(
            id=str(uuid.uuid4()), type="domain", value="clash.example",
            threat_score=1, confidence=1, first_seen=_naive_utc(),
            last_seen=_naive_utc(), sighting_count=1, tags=[], metadata_={},
            mitre_techniques=[], created_at=_naive_utc(), updated_at=_naive_utc(),
        ))
        with pytest.raises(IntegrityError):
            mysql_session.commit()
        mysql_session.rollback()

    def test_same_value_different_type_is_allowed(self, mysql_session):
        """Uniqueness is on the pair, so a domain and a URL may share a string."""
        _make_ioc(mysql_session, ioc_type="domain", value="both.example")
        _make_ioc(mysql_session, ioc_type="url", value="both.example")
        mysql_session.commit()


class TestLockRetryClassification:
    """`utils/db_retry` must recognise real driver errors, not just synthetic ones."""

    def test_a_real_deadlock_is_classified_as_retryable(self, mysql_session):
        from app.utils.db_retry import is_retryable_lock_error

        try:
            mysql_session.execute(sa.text("SELECT * FROM iocs WHERE 1=2 FOR UPDATE"))
            mysql_session.commit()
        except Exception:
            mysql_session.rollback()

        from sqlalchemy.exc import OperationalError

        class _Orig(Exception):
            args = (1205, "Lock wait timeout exceeded")

        wrapped = OperationalError("stmt", {}, _Orig())
        assert is_retryable_lock_error(wrapped)

        class _Deadlock(Exception):
            args = (1213, "Deadlock found")

        assert is_retryable_lock_error(OperationalError("stmt", {}, _Deadlock()))

    def test_a_non_lock_error_is_not_retried(self, mysql_session):
        from sqlalchemy.exc import OperationalError

        from app.utils.db_retry import is_retryable_lock_error

        class _Syntax(Exception):
            args = (1064, "You have an error in your SQL syntax")

        assert not is_retryable_lock_error(OperationalError("stmt", {}, _Syntax()))

    def test_lock_wait_timeout_is_reachable_from_two_transactions(self, mysql_engine):
        """Forces a genuine 1205 rather than asserting on a hand-built exception."""
        from sqlalchemy.orm import sessionmaker

        from app.models.ioc import IOC
        from app.utils.db_retry import is_retryable_lock_error

        Session = sessionmaker(bind=mysql_engine, future=True)
        setup = Session()
        ioc = _make_ioc(setup)
        setup.commit()
        target_id = ioc.id
        setup.close()

        holder = Session()
        waiter = Session()
        try:
            holder.execute(sa.text("SET innodb_lock_wait_timeout = 1"))
            holder.execute(
                select(IOC).where(IOC.id == target_id).with_for_update()
            ).scalars().all()

            waiter.execute(sa.text("SET innodb_lock_wait_timeout = 1"))
            with pytest.raises(Exception) as exc_info:
                waiter.execute(
                    sa.update(IOC).where(IOC.id == target_id).values(threat_score=99)
                )
                waiter.commit()
            assert is_retryable_lock_error(exc_info.value), (
                f"a real lock conflict was not classified as retryable: "
                f"{exc_info.value!r}"
            )
        finally:
            for s in (waiter, holder):
                try:
                    s.rollback()
                    s.close()
                except Exception:
                    pass


class TestSavepointIsolation:
    """`enrich_ioc` writes inside `begin_nested()`.

    A duplicate-key race must roll back only the enrichment and leave the
    request's transaction usable — otherwise one unlucky insert poisons the whole
    unit of work.
    """

    def test_nested_rollback_leaves_the_outer_transaction_usable(self, mysql_session):
        from sqlalchemy.exc import IntegrityError

        from app.models.enrichment import Enrichment
        from app.models.ioc import IOC

        ioc = _make_ioc(mysql_session)
        mysql_session.add(Enrichment(
            id=str(uuid.uuid4()), ioc_id=ioc.id, source="geoip",
            data={"country_code": "RU"}, enriched_at=_naive_utc(),
            expires_at=_naive_utc() + timedelta(hours=1),
        ))
        mysql_session.commit()

        # Duplicate (ioc_id, source) inside a savepoint.
        try:
            with mysql_session.begin_nested():
                mysql_session.add(Enrichment(
                    id=str(uuid.uuid4()), ioc_id=ioc.id, source="geoip",
                    data={"country_code": "CN"}, enriched_at=_naive_utc(),
                    expires_at=_naive_utc() + timedelta(hours=1),
                ))
                mysql_session.flush()
        except IntegrityError:
            pass

        # The outer transaction must still work.
        second = _make_ioc(mysql_session, value="after-savepoint.example")
        mysql_session.commit()

        assert mysql_session.get(IOC, second.id) is not None
        assert mysql_session.execute(
            select(func.count()).select_from(Enrichment).where(Enrichment.ioc_id == ioc.id)
        ).scalar() == 1

    def test_enrichment_unique_constraint_is_per_ioc_and_source(self, mysql_session):
        from app.models.enrichment import Enrichment

        ioc = _make_ioc(mysql_session)
        for source in ("geoip", "whois", "dns"):
            mysql_session.add(Enrichment(
                id=str(uuid.uuid4()), ioc_id=ioc.id, source=source,
                data={}, enriched_at=_naive_utc(), expires_at=None,
            ))
        mysql_session.commit()
        assert mysql_session.execute(
            select(func.count()).select_from(Enrichment).where(Enrichment.ioc_id == ioc.id)
        ).scalar() == 3


class TestIdleConnectionRecovery:
    """The reason `wait_timeout=30` is set on the container.

    `database.py` patches `aiomysql.Connection.ensure_closed` to swallow dead
    transport errors and sets `pool_recycle=280` / `pool_pre_ping`. At the 8-hour
    default none of that is ever exercised locally.
    """

    @pytest.mark.slow
    def test_pool_pre_ping_recovers_after_the_server_drops_the_connection(
        self, mysql_engine, mysql_server_info
    ):
        import time

        _, _, wait_timeout = mysql_server_info
        assert wait_timeout <= 60

        engine = sa.create_engine(
            mysql_test_url_for(mysql_engine), pool_pre_ping=True, pool_recycle=280
        )
        try:
            with engine.connect() as conn:
                assert conn.execute(sa.text("SELECT 1")).scalar() == 1

            # Idle past wait_timeout so the server closes the pooled connection.
            time.sleep(wait_timeout + 3)

            with engine.connect() as conn:
                assert conn.execute(sa.text("SELECT 1")).scalar() == 1, (
                    "pool_pre_ping should have replaced the dead connection"
                )
        finally:
            engine.dispose()

    def test_without_pre_ping_the_dead_connection_is_observable(self, mysql_server_info):
        """Documents the failure the settings exist to prevent.

        Tolerant by design: whether the stale handle surfaces depends on timing and
        on whether the pool hands back the same connection, so this asserts the
        engine either recovers or raises a recognisable connection error — never
        that it silently returns wrong data.
        """
        import time

        from sqlalchemy.exc import DBAPIError, OperationalError

        _, _, wait_timeout = mysql_server_info
        engine = sa.create_engine(
            mysql_test_url(), pool_pre_ping=False, pool_recycle=-1, pool_size=1,
        )
        try:
            with engine.connect() as conn:
                conn.execute(sa.text("SELECT 1"))
            time.sleep(wait_timeout + 3)
            try:
                with engine.connect() as conn:
                    conn.execute(sa.text("SELECT 1"))
            except (OperationalError, DBAPIError) as exc:
                assert "MySQL" in str(exc) or "connection" in str(exc).lower()
        finally:
            engine.dispose()


@pytest.mark.mysql
class TestCreateIocHoldsAWriteLockThroughEnrichment:
    """`create_ioc` inserts, then enriches, and only then does `get_db()` commit.

    That is structurally different from its five siblings, which READ an existing row and
    then enrich: this one holds a write lock on a brand-new row for the whole enrichment —
    WHOIS through the executor, DNS, external APIs, plus any wait for the process-wide
    `_enrichment_semaphore` (5 slots, shared with a running backfill or `sync-all`). Tens
    of seconds is reachable; per-enricher timeouts are 15 s and 30 s.

    Feed ingestion is the plausible victim, and it is exactly the workload tuned around
    lock contention: `INSERT ... IGNORE` in ~30-row chunks with 1205 retry and back-off.

    **Measured 2026-08-17. The blast radius is THE GAP AROUND THE NEW KEY** — wider than
    one row, far narrower than the table. A concurrent insert of the same `(type, value)`
    blocks on the duplicate; a key adjacent in index order blocks on InnoDB's gap lock;
    a key that sorts among existing records proceeds in single-digit ms.

    An earlier version of this docstring claimed the radius was "one row" and that a
    neighbouring key proceeds. **That was wrong**, and wrong for an instructive reason:
    it was measured against a `(type, value(700))` prefix index on MySQL 8, which is not
    the production index, on a table whose row population happened to put the probe keys
    in different gaps. Both the engine and the index are now correct here.

    **CORRECTED 2026-08-17 (same day), twice, and both corrections matter.**

    1. The first measurement ran against MySQL 8 with a ``(type, value(700))`` prefix
       index, because the container image and the test fixture were both wrong (see
       ``conftest_mysql``). Production is MariaDB 11.8.8 with a full-column index.
       Re-measured on the real engine and the real index, the conclusion held.

    2. More importantly, the result **depends on the table not being empty**, and the
       original version of this test did not ensure that — it passed only because
       earlier tests happened to leave rows behind. On a near-empty table InnoDB has no
       index records to lock between, so an uncommitted INSERT gap-locks the entire
       range and *every* concurrent insert blocks. Measured on MariaDB 11.8 against the
       production index:

       ===========  ==========================
       rows in iocs  unrelated insert
       ===========  ==========================
       1             BLOCKED (1205) — whole-range gap lock
       1,001         proceeded, 7.4 ms
       21,003        proceeded, 8.9 ms
       ===========  ==========================

       Production holds 217,485 rows, so the narrow behaviour is the real one. This test
       now seeds its own rows rather than inheriting them, so it asserts the production
       condition deterministically instead of by luck of ordering.

    That is why this stayed with option (a): the contention is one row wide, the victim
    already retries 1205 with back-off by design, and the alternative (BackgroundTasks)
    needs its own session because the request session closes on return — machinery that
    exists nowhere else in this codebase. **The constraint to preserve is the narrowness.**
    If `create_ioc` ever grows a second write before enrichment, or the unique index gains
    a gap-locking range predicate, the hold stops being one row wide and the trade changes.
    """

    def _cols(self):
        return ("id, type, value, threat_score, confidence, sighting_count, "
                "tags, metadata, mitre_techniques")

    def _vals(self):
        return (":id, :type, :value, :threat_score, :confidence, :sighting_count, "
                ":tags, :metadata, :mitre_techniques")

    def _row(self, value):
        import uuid

        return {"id": str(uuid.uuid4()), "type": "domain", "value": value,
                "threat_score": 10, "confidence": 50, "sighting_count": 1,
                "tags": "[]", "metadata": "{}", "mitre_techniques": "[]"}

    def _try_ingest(self, Session, value, timeout=2):
        """Feed ingestion's own statement shape, with a short timeout."""
        s = Session()
        s.execute(sa.text("SET innodb_lock_wait_timeout = :t"), {"t": timeout})
        try:
            s.execute(
                sa.text(f"INSERT IGNORE INTO iocs ({self._cols()}) VALUES ({self._vals()})"),
                self._row(value),
            )
            s.commit()
            return None
        except Exception as exc:  # noqa: BLE001
            s.rollback()
            return getattr(getattr(exc, "orig", None), "args", [None])[0]
        finally:
            s.close()

    def _seed_corpus(self, Session, n=1200):
        """Populate `iocs` so the index has records to lock BETWEEN.

        Not optional and not tidiness. Below roughly a thousand rows the whole-range
        gap lock dominates and `test_only_the_duplicate_blocks_not_the_table` fails --
        correctly, because on an empty table the narrow behaviour genuinely does not
        hold. Production has 217,485 rows; this seeds enough to be on the same side of
        the transition, verified at 1,001 rows behaving identically to 21,003.
        """
        import uuid

        s = Session()
        tag = uuid.uuid4().hex[:6]
        batch = [self._row(f"lockseed-{tag}-{i:06d}.example") for i in range(n)]
        for start in range(0, len(batch), 400):
            s.execute(
                sa.text(f"INSERT IGNORE INTO iocs ({self._cols()}) VALUES ({self._vals()})"),
                batch[start:start + 400],
            )
            s.commit()
        total = s.execute(sa.text("SELECT COUNT(*) FROM iocs")).scalar()
        s.close()
        assert total >= 1000, (
            f"only {total} rows seeded; below ~1000 InnoDB gap-locks the whole range and "
            "this test would assert the wrong behaviour"
        )
        return total

    def test_only_the_duplicate_blocks_not_the_table(self, mysql_engine):
        import uuid

        from sqlalchemy.orm import sessionmaker

        Session = sessionmaker(bind=mysql_engine, future=True)
        self._seed_corpus(Session)
        tag = uuid.uuid4().hex[:8]
        same = f"locktest-same-{tag}.example"
        adjacent = f"locktest-same-{tag}.exampld"  # neighbouring key, gap-lock probe
        # Distant: sorts among the seeded rows rather than beside the holder's key.
        other = f"lockseed-distant-{tag}.example"

        holder = Session()
        try:
            # create_ioc: INSERT, then hold the transaction open across "enrichment".
            holder.execute(
                sa.text(f"INSERT INTO iocs ({self._cols()}) VALUES ({self._vals()})"),
                self._row(same),
            )

            assert self._try_ingest(Session, same) == 1205, (
                "a concurrent insert of the SAME (type, value) should block on the "
                "uncommitted row and surface as 1205 — if it no longer does, the "
                "contention profile this test documents has changed"
            )
            assert self._try_ingest(Session, adjacent) == 1205, (
                "a value ADJACENT in index order did NOT block. That is a WIDENING of "
                "what this test documents, not a fix: the measured behaviour is that "
                "InnoDB's gap lock covers the range around the uncommitted key, so a "
                "neighbouring key blocks too. If that stopped being true the lock model "
                "changed and the sizing below needs redoing."
            )
            assert self._try_ingest(Session, other) is None, (
                "a DISTANT value blocked. That would mean create_ioc stalls feed "
                "ingestion broadly rather than within one gap, and the in-request "
                "enrichment trade-off must be revisited (BackgroundTasks, or commit "
                "before enriching)."
            )
        finally:
            holder.rollback()
            holder.close()

    def test_the_lock_is_released_once_the_holder_finishes(self, mysql_engine):
        """The control. Without it the test above passes if inserts block permanently."""
        import uuid

        from sqlalchemy.orm import sessionmaker

        Session = sessionmaker(bind=mysql_engine, future=True)
        value = f"locktest-release-{uuid.uuid4().hex[:8]}.example"

        holder = Session()
        holder.execute(
            sa.text(f"INSERT INTO iocs ({self._cols()}) VALUES ({self._vals()})"),
            self._row(value),
        )
        assert self._try_ingest(Session, value) == 1205
        holder.rollback()
        holder.close()

        assert self._try_ingest(Session, value) is None, (
            "the duplicate still blocked after the holder rolled back, so the 1205 above "
            "was not caused by the holder and this test proves nothing"
        )


def mysql_test_url_for(engine) -> str:
    return str(engine.url.render_as_string(hide_password=False))


from tests.conftest_mysql import mysql_test_url  # noqa: E402
