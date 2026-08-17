"""Phase 4 Section B — reads are chunked at 500, writes stay at 30.

The 30-row chunk exists to hold InnoDB row locks for one ``executemany`` UPDATE rather
than across a Python loop. That is a WRITE property; plain SELECTs under REPEATABLE READ
take no row locks, so the read phase was paying a lock-contention tax it does not owe.

Three reads run per chunk before any write — the ``iocs`` lookup, the grouped
distinct-feed count, and the already-linked set. Coupled to the write chunk they cost one
round-trip per ten rows; decoupled they cost one per 167.

**Counted, not asserted.** These run in the mysql tier against a real server because the
property is "how many statements reach the database", and a mocked session cannot answer
that — it is the same reasoning as ``test_query_budget.py``. Local latency is ~0.1 ms
against 50–300 ms from Render to Hostinger, so timing here would be meaningless while
statement count transfers directly.

THE LOAD-BEARING ASSUMPTION IS ``expire_on_commit=False``. The prefetched map holds ORM
objects that must survive the write sub-batches' commits. Under SQLAlchemy's default
(``True``) every one of them would expire on the first commit and the next attribute
access would issue a refresh SELECT — a per-row N+1 that would more than undo the saving,
and it would not show up in any test that did not count statements. That is precisely
what ``test_statements_do_not_scale_with_the_write_chunk_count`` is watching for.
"""

import uuid

import pytest
import sqlalchemy as sa

pytestmark = pytest.mark.mysql


def _rows(n, tag):
    """`n` normalised ingest rows, shaped as `_make_ioc` produces them."""
    return [
        {
            "type": "domain",
            "value": f"readchunk-{tag}-{i:05d}.example",
            "threat_score": 10,
            "confidence": 50,
            "tags": [],
            "metadata": {},
            "mitre_techniques": [],
            "first_seen": None,
            "last_seen": None,
        }
        for i in range(n)
    ]


def _feed(session, slug):
    from app.models.feed import FeedSource

    feed = FeedSource(
        id=str(uuid.uuid4()), name=slug, slug=slug,
        url="http://example.invalid", feed_type="csv", is_enabled=True,
    )
    session.add(feed)
    session.commit()
    return feed


class TestReadChunkSizing:
    def test_the_read_chunk_is_larger_than_the_write_chunk(self):
        """The constants themselves. Cheap, and it states the invariant."""
        from app.services.feed_ingestion import (
            _DEFAULT_BATCH_SIZE,
            _READ_CHUNK_SIZE,
        )

        assert _READ_CHUNK_SIZE > _DEFAULT_BATCH_SIZE, (
            "the read chunk is no larger than the write chunk, so Section B's decoupling "
            "buys nothing"
        )
        assert _DEFAULT_BATCH_SIZE == 30, (
            "the WRITE chunk moved. It is 30 to bound how long InnoDB row locks are held "
            "for one executemany UPDATE; raising it is the change the chunking exists to "
            "prevent, and a 500-row write batch would hold locks across ~17 statements."
        )

    def test_expire_on_commit_is_false(self):
        """Stated as a test because the whole design rests on it.

        With the default True, the prefetched ORM objects expire at the first write
        sub-batch commit and every later attribute read becomes a refresh SELECT.
        """
        from app.database import AsyncSessionLocal

        assert AsyncSessionLocal.kw.get("expire_on_commit") is False, (
            "AsyncSessionLocal now expires objects on commit. The Section B prefetch "
            "carries ORM rows across several sub-batch commits, so this would turn each "
            "later attribute access into a per-row refresh SELECT — an N+1 that silently "
            "undoes the read-chunk saving."
        )


@pytest.mark.mysql
class TestStatementCountsAgainstARealServer:
    """The measurement. Counted on the wire, not inferred from the source."""

    @pytest.mark.asyncio
    async def test_statements_do_not_scale_with_the_write_chunk_count(
        self, mysql_engine, mysql_async_url
    ):
        """450 rows = 15 write chunks but ONE read chunk.

        `mysql_engine` is requested only for its schema-creation side effect; the
        counting engine below is separate so the fixture's own statements are not
        counted.

        If reads were still coupled to the write chunk, the three lock-free reads would
        run 15 times (45 statements) instead of once (3). If `expire_on_commit` were True,
        there would additionally be a refresh SELECT per prefetched row.

        The assertion is a ceiling rather than an equality: the write path's statement
        count is not what this test is about, and pinning it would make the test fail for
        unrelated reasons.
        """
        from sqlalchemy.ext.asyncio import async_sessionmaker, create_async_engine

        from app.services.feed_ingestion import ingest_iocs

        engine = create_async_engine(mysql_async_url)
        counted = {"n": 0}

        @sa.event.listens_for(engine.sync_engine, "before_cursor_execute")
        def _count(conn, cursor, statement, params, context, executemany):
            counted["n"] += 1

        Session = async_sessionmaker(engine, expire_on_commit=False)
        tag = uuid.uuid4().hex[:6]

        try:
            # Seed the feed with a sync session so its statements are not counted.
            from sqlalchemy.orm import sessionmaker

            sync_engine = sa.create_engine(
                mysql_async_url.replace("mysql+aiomysql://", "mysql+pymysql://")
            )
            SyncSession = sessionmaker(bind=sync_engine)
            s = SyncSession()
            feed = _feed(s, f"readchunk-{tag}")
            feed_id = feed.id
            s.close()
            sync_engine.dispose()

            rows = _rows(450, tag)
            async with Session() as session:
                result = await session.execute(
                    sa.select(sa.text("1")).select_from(sa.text("dual"))
                )
                result.all()
                counted["n"] = 0  # ignore warm-up

                from app.models.feed import FeedSource

                fresh = (await session.execute(
                    sa.select(FeedSource).where(FeedSource.id == feed_id)
                )).scalar_one()
                counted["n"] = 0

                # POPULATE FIRST, then measure the SECOND pass. This is not incidental:
                # on a first sync every row is new, so `existing_map` is empty, and
                # `_distinct_feed_counts_async` / `_already_linked_async` short-circuit
                # on an empty id list without issuing a query. Only ONE of the three
                # reads actually runs, and the coupled/decoupled counts are 77 vs 63 --
                # both under any sane ceiling, so the test would pass with the feature
                # reverted. Measured, and it was the first version of this test.
                #
                # The steady state is the case that matters anyway: URLhaus and the
                # full-list exports republish rows that already exist, which is when all
                # three reads run and the decoupling is worth something.
                await ingest_iocs(session, fresh, rows, batch_size=30)
                counted["n"] = 0
                await ingest_iocs(session, fresh, rows, batch_size=30)

            total = counted["n"]
            # MEASURED on MariaDB 11.8, 450 rows / 15 write chunks, steady state:
            #   reads coupled to the write chunk : 106 statements
            #   reads at 500                     :  64 statements
            # The 42-statement difference is exactly the predicted read saving
            # (15 chunks x 3 reads = 45, down to 1 x 3 = 3). The ceiling sits between
            # the two so the test fails if the coupling returns.
            assert total < 85, (
                f"{total} statements for 450 rows in 15 write chunks. That is consistent "
                "with reads still running per write chunk (or with prefetched rows being "
                "expired on commit and refreshed one at a time). Section B's decoupling "
                "is not in effect."
            )
        finally:
            await engine.dispose()

    @pytest.mark.asyncio
    async def test_a_larger_corpus_does_not_multiply_the_read_cost(
        self, mysql_engine, mysql_async_url
    ):
        """Tripling the rows must not triple the per-row statement cost.

        Scaling is the property that matters — an absolute count can be tuned into
        passing, a slope cannot.
        """
        from sqlalchemy.ext.asyncio import async_sessionmaker, create_async_engine
        from sqlalchemy.orm import sessionmaker

        from app.models.feed import FeedSource
        from app.services.feed_ingestion import ingest_iocs

        engine = create_async_engine(mysql_async_url)
        counted = {"n": 0}

        @sa.event.listens_for(engine.sync_engine, "before_cursor_execute")
        def _count(conn, cursor, statement, params, context, executemany):
            counted["n"] += 1

        Session = async_sessionmaker(engine, expire_on_commit=False)
        measured = {}
        try:
            for size in (150, 450):
                tag = uuid.uuid4().hex[:6]
                sync_engine = sa.create_engine(
                    mysql_async_url.replace("mysql+aiomysql://", "mysql+pymysql://")
                )
                s = sessionmaker(bind=sync_engine)()
                feed_id = _feed(s, f"scale-{tag}").id
                s.close()
                sync_engine.dispose()

                async with Session() as session:
                    fresh = (await session.execute(
                        sa.select(FeedSource).where(FeedSource.id == feed_id)
                    )).scalar_one()
                    counted["n"] = 0
                    await ingest_iocs(session, fresh, _rows(size, tag), batch_size=30)
                    measured[size] = counted["n"]

            per_row_small = measured[150] / 150
            per_row_large = measured[450] / 450
            assert per_row_large <= per_row_small * 1.2, (
                f"per-row statement cost rose with corpus size "
                f"({per_row_small:.3f} -> {per_row_large:.3f} statements/row). Reads are "
                "scaling with the row count rather than the read-chunk count."
            )
        finally:
            await engine.dispose()
