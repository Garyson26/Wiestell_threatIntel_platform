"""Measured statement and write volume of the ingest path, against real MySQL.

    docker compose up -d db
    python -m pytest -m mysql tests/test_ingest_write_volume.py -s

Two changes are measured here, both of which move stored scores:

* **Section 0.5** — the re-read path recomputes ``threat_score`` and used to do so
  without ``enrichment_data``, collapsing the enrichment-risk term to its 20.0 floor
  and the reputation term (which resolves the reputation payload *and*, for CVEs, the
  NVD CVSS score out of that same list) to ``NEUTRAL_REPUTATION``. Measured cost of
  one re-read on a fully enriched indicator: -23 for an IP or URL, -44 for a KEV CVE.
* **Section 3** — the re-read gate. Rows whose evidence has not changed are skipped
  entirely: no ``UPDATE``, no ``sighting_count`` increment, no ``last_seen`` rewrite
  and no enrichment fetch.

Everything here exercises the **async** path, which is the one production runs. A
synchronous mirror existed until 2026-07-31 and these tests used to target it, so the
numbers were coming from code that ran nowhere. Deleting it removed both the two-copy
drift risk and that inversion.

The ``-s`` flag is worth using: these tests print what they measure.
"""

from __future__ import annotations

import uuid
from datetime import datetime, timedelta, timezone

import pytest
import sqlalchemy as sa

from app.feeds.base import BaseFeed
from tests.conftest_mysql import attach_counter, detach_counter, mysql_test_url

pytestmark = pytest.mark.mysql

CHUNK = 30


def _naive_utc() -> datetime:
    return datetime.now(timezone.utc).replace(tzinfo=None)


def _async_url() -> str:
    return mysql_test_url().replace("mysql+pymysql://", "mysql+aiomysql://")


class _Connector(BaseFeed):
    """Minimal real connector, so IOC dicts come from the actual ``_make_ioc``.

    Hand-rolled dicts were a mistake in an earlier version of this file: they omit
    ``_source_timestamped``, which ``_make_ioc`` sets and the re-read gate reads, so
    the gate never fired and the tests reported a code failure that was a fixture
    bug. Every connector in the repo goes through ``_make_ioc``, so this is also the
    faithful shape.
    """

    name, slug, feed_type, url = "test", "test", "csv", "https://example.invalid/f"

    async def fetch(self):  # pragma: no cover - not exercised
        return ""

    async def parse(self, raw_data):  # pragma: no cover - not exercised
        return []


_CONNECTOR = _Connector(api_key=None)


def _raw(i: int, *, seen_days_ago: int = 2, tags=None, timestamped: bool = True) -> dict:
    """One parsed IOC, built exactly as a connector would build it."""
    seen = datetime.now(timezone.utc) - timedelta(days=seen_days_ago)
    return _CONNECTOR._make_ioc(
        ioc_type="url",
        value=f"http://volume-{i}.example/path",
        tags=tags if tags is not None else ["malware"],
        confidence=70,
        metadata={"source": "test"},
        first_seen=seen if timestamped else None,
        last_seen=seen if timestamped else None,
    )


@pytest.fixture
async def ingest(mysql_session):
    """Async ingest harness: ``(run, make_feed, read, add_enrichment, ids, counter)``.

    Depends on ``mysql_session`` for its **truncation side effect**, not to use it:
    that fixture empties every table before each test. Depending on ``mysql_engine``
    directly instead left state to accumulate across tests in one process, which
    produced a case that passed alone and failed in the file — the kind of
    order-dependence that is worth removing rather than asserting around.

    The work itself goes through a separate async engine, because the ingest path is
    async and ``mysql_session`` is a sync session.
    """
    from sqlalchemy.ext.asyncio import async_sessionmaker, create_async_engine

    from app.models.enrichment import Enrichment
    from app.models.feed import FeedSource
    from app.models.ioc import IOC
    from app.services.feed_ingestion import _ingest_chunk

    engine = create_async_engine(_async_url(), pool_pre_ping=True)
    Session = async_sessionmaker(engine, expire_on_commit=False)
    counter = attach_counter(engine.sync_engine)

    async def make_feed(slug: str) -> str:
        async with Session() as session:
            feed = FeedSource(
                id=str(uuid.uuid4()), name=slug, slug=slug, feed_type="csv",
                url="https://example.invalid/feed", is_enabled=True,
                sync_frequency=3600, ioc_count=0, config={},
                created_at=_naive_utc(),
            )
            session.add(feed)
            await session.commit()
            return feed.id

    async def run(feed_id: str, batch: list) -> int:
        """One ingest chunk, committed — exactly what a sync does per chunk."""
        async with Session() as session:
            feed = (await session.execute(
                sa.select(FeedSource).where(FeedSource.id == feed_id)
            )).scalar_one()
            processed = await _ingest_chunk(session, feed, batch)
            await session.commit()
            return processed

    async def read(value: str):
        async with Session() as session:
            return (await session.execute(
                sa.select(IOC).where(IOC.value == value)
            )).scalar_one()

    async def add_enrichment(ioc_id: str, source="reputation", data=None):
        payload = data if data is not None else {
            "aggregate_score": 80, "sources_checked": 1,
            "providers": [{"name": "abuseipdb", "supports_type": True,
                           "configured": True, "responded": True,
                           "verdict": "malicious", "corroboration": 42}],
        }
        async with Session() as session:
            session.add(Enrichment(
                id=str(uuid.uuid4()), ioc_id=ioc_id, source=source, data=payload,
                enriched_at=_naive_utc(),
                expires_at=_naive_utc() + timedelta(hours=6),
            ))
            await session.commit()

    async def all_ioc_ids():
        async with Session() as session:
            return [r[0] for r in (await session.execute(
                sa.select(IOC.id).where(IOC.value.like("http://volume-%"))
            )).all()]

    try:
        yield run, make_feed, read, add_enrichment, all_ioc_ids, counter
    finally:
        detach_counter(counter)
        await engine.dispose()


class TestStatementVolume:
    async def test_a_changed_re_read_costs_one_enrichment_query(self, ingest):
        """When the gate lets rows through, enrichment is ONE query for 30 rows."""
        run, make_feed, _read, add_enrichment, all_ioc_ids, counter = ingest
        feed_id = await make_feed("urlhaus-volume")
        batch = [_raw(i) for i in range(CHUNK)]
        await run(feed_id, batch)

        for ioc_id in await all_ioc_ids():
            await add_enrichment(ioc_id)

        advanced = [
            dict(r, last_seen=r["last_seen"] + timedelta(days=1)) for r in batch
        ]
        counter.reset()
        await run(feed_id, advanced)

        enrichment_reads = counter.matching("from enrichments")
        print(f"\n  changed re-read of {CHUNK} rows: {counter.count} statements, "
              f"{len(enrichment_reads)} enrichment SELECT")
        print(f"\n{counter.summary()}")

        assert len(enrichment_reads) == 1, counter.summary()
        assert counter.count < CHUNK, (
            f"{counter.count} statements for {CHUNK} rows suggests an N+1\n"
            f"{counter.summary()}"
        )

    async def test_an_all_unchanged_re_read_writes_and_fetches_nothing(self, ingest):
        """Section 3's headline effect.

        Before the gate every re-read issued an executemany UPDATE over all 30 rows
        even when nothing had changed. At 15,524 URLhaus rows four times a day that
        is the InnoDB contention scenario the chunking exists for, almost all of it
        rewriting identical values. The enrichment fetch disappears too, because it
        is issued only for rows the gate lets through.
        """
        run, make_feed, _read, _add, _ids, counter = ingest
        feed_id = await make_feed("urlhaus-unchanged")
        batch = [_raw(1000 + i) for i in range(CHUNK)]
        await run(feed_id, batch)

        counter.reset()
        processed = await run(feed_id, batch)

        updates = counter.matching("update iocs")
        enrichment_reads = counter.matching("from enrichments")
        print(f"\n  all-unchanged re-read of {CHUNK} rows:")
        print(f"    total statements   : {counter.count}")
        print(f"    UPDATE iocs        : {len(updates)}")
        print(f"    SELECT enrichments : {len(enrichment_reads)}")
        print(f"\n{counter.summary()}")

        assert len(updates) == 0, f"gate did not suppress the UPDATE\n{counter.summary()}"
        assert len(enrichment_reads) == 0, (
            "enrichment fetched for a chunk with nothing to re-score — the fetch must "
            f"come after the gate\n{counter.summary()}"
        )
        assert processed == CHUNK, "rows must still count as processed"


class TestEnrichmentSurvivesReRead:
    async def test_the_enrichment_informed_score_is_applied_on_re_read(self, ingest):
        """Section 0.5's behavioural assertion."""
        run, make_feed, read, add_enrichment, _ids, _counter = ingest
        feed_id = await make_feed("urlhaus-score")
        batch = [_raw(9001)]
        await run(feed_id, batch)

        before = await read(batch[0]["value"])
        unenriched = before.threat_score
        await add_enrichment(before.id)

        # Advance the source timestamp so the gate re-scores the row. An unchanged
        # re-read now preserves the enriched score by not touching it at all.
        advanced = [dict(batch[0], last_seen=batch[0]["last_seen"] + timedelta(days=1))]
        await run(feed_id, advanced)

        after = await read(batch[0]["value"])
        print(f"\n  unenriched first ingest     : {unenriched}")
        print(f"  after re-read w/ enrichment : {after.threat_score}")
        assert after.threat_score > unenriched, (
            f"the re-read did not pick up enrichment ({unenriched} -> "
            f"{after.threat_score})"
        )


class TestSightingAndRecency:
    async def test_repeated_identical_syncs_do_not_inflate_the_counter(self, ingest):
        """`sighting_count` counted downloads of a file, not observations."""
        run, make_feed, read, _add, _ids, _counter = ingest
        feed_id = await make_feed("urlhaus-counter")
        batch = [_raw(4242)]
        await run(feed_id, batch)

        first = await read(batch[0]["value"])
        assert first.sighting_count == 1
        source_ts = first.last_seen

        for _ in range(5):
            await run(feed_id, batch)

        after = await read(batch[0]["value"])
        print(f"\n  sighting_count after 1 + 5 identical syncs  : {after.sighting_count}")
        print(f"  last_seen still the source's own timestamp : "
              f"{after.last_seen == source_ts}")
        assert after.sighting_count == 1, (
            f"counter tracked re-reads: {after.sighting_count} after 6 identical syncs"
        )
        assert after.last_seen == source_ts, "last_seen was overwritten with ingest time"

    async def test_an_advancing_source_timestamp_does_increment(self, ingest):
        """The gate must not suppress genuine re-observation."""
        run, make_feed, read, _add, _ids, _counter = ingest
        feed_id = await make_feed("urlhaus-advance")
        batch = [_raw(555)]
        await run(feed_id, batch)

        advanced = dict(batch[0], last_seen=batch[0]["last_seen"] + timedelta(days=1))
        await run(feed_id, [advanced])

        row = await read(advanced["value"])
        print(f"\n  sighting_count after a genuine re-observation: {row.sighting_count}")
        assert row.sighting_count == 2
        # Microseconds are normalised away on write — see _source_observed_at.
        assert row.last_seen == advanced["last_seen"].replace(
            tzinfo=None, microsecond=0
        )


class TestGateDisjunction:
    """The gate is `timestamp OR new-source-link OR tags OR techniques`.

    A pure timestamp check would have silently undone Section 0.5 for two of these.
    """

    async def test_a_second_feed_reporting_the_same_ioc_is_not_skipped(self, ingest):
        """A new feed link takes source_count 1 -> 2, so diversity goes 30 -> 60.

        That is 20% of the default composite, and `last_seen` does not move — so a
        timestamp-only gate would leave a stale single-source score indefinitely.
        """
        run, make_feed, read, _add, _ids, _counter = ingest
        feed_a = await make_feed("feed-a")
        feed_b = await make_feed("feed-b")
        batch = [_raw(777)]

        await run(feed_a, batch)
        single = (await read(batch[0]["value"])).threat_score

        await run(feed_b, batch)          # same IOC, same timestamps, new feed
        both = await read(batch[0]["value"])

        print(f"\n  one feed: {single}   two feeds: {both.threat_score}")
        assert both.threat_score > single, (
            "the second feed's corroboration was not scored — the gate is missing its "
            "new-source-link term"
        )
        # Corroboration is a different axis from re-observation.
        assert both.sighting_count == 1

    async def test_changed_tags_are_not_skipped(self, ingest):
        """Tags feed the context term; re-classification is new information."""
        run, make_feed, read, _add, _ids, _counter = ingest
        feed_id = await make_feed("urlhaus-tags")
        batch = [_raw(888)]
        await run(feed_id, batch)

        retagged = dict(batch[0], tags=["malware", "ransomware"])
        await run(feed_id, [retagged])

        row = await read(batch[0]["value"])
        assert "ransomware" in (row.tags or []), "the new tag was not merged"


class TestSyncPathIsGone:
    """Item 4: one implementation, so the two copies cannot drift again.

    They drifted twice inside a single change set — an unbound `enrichment_map` and a
    `new_ioc_rows` NameError — both in the sync half, both invisible to compileall
    because no test exercised those lines.
    """

    def test_the_synchronous_mirror_no_longer_exists(self):
        from app.services import feed_ingestion

        for name in ("ingest_iocs_sync", "_ingest_chunk_sync",
                     "_process_chunk_with_retry", "_distinct_feed_counts_sync",
                     "_already_linked_sync", "_enrichments_for_sync"):
            assert not hasattr(feed_ingestion, name), (
                f"{name} is back — the sync mirror was deleted on 2026-07-31 because "
                "maintaining two copies of the ingest path caused repeated drift. "
                "Wrap the async path with asyncio.run instead."
            )

    def test_the_celery_task_drives_the_async_path(self):
        import inspect

        from app.tasks import feed_tasks

        # Check for a *call*, not a mention: the module comments explain why the
        # sync mirror was deleted, so a substring test on the name matches the
        # explanation and fails for the wrong reason.
        import ast

        tree = ast.parse(inspect.getsource(feed_tasks))
        called = {
            getattr(n.func, "id", None) or getattr(n.func, "attr", None)
            for n in ast.walk(tree) if isinstance(n, ast.Call)
        }
        assert "ingest_iocs_sync" not in called
        assert "ingest_iocs" in called, "the task no longer ingests at all"
        assert "run" in called, "expected asyncio.run to drive the async path"


class TestFullListExports:
    """59.9% of per-sync record volume comes from feeds with no record timestamps.

    Measured 2026-07-31: 30,826 records across blocklist.de (23,112), eCrimeLabs
    (3,195), MISP CERT-FR (2,277), CISA KEV (1,656) and Emerging Threats (586),
    against 20,653 from the timestamped feeds.

    Because `_make_ioc` defaults an absent timestamp to now(), the re-read gate could
    not fire for any of them and `sighting_count` incremented on every sync —
    saturating `_sighting_frequency_score` at 100.0 within about a day.

    Two kinds, and the distinction matters more than the fact of being a full list:
    a list that EXPIRES entries re-asserts liveness (advance `last_seen`), while one
    that only GROWS says nothing about today (freeze both).
    """

    def test_current_state_lists_are_declared_as_such(self):
        from app.feeds.base import FULL_LIST_CURRENT_STATE
        from app.feeds.blocklist_de import BlocklistDeFeed
        from app.feeds.emergingthreats import EmergingThreatsFeed

        for connector in (BlocklistDeFeed, EmergingThreatsFeed):
            assert connector.full_list_kind == FULL_LIST_CURRENT_STATE, connector.__name__

    def test_cumulative_catalogues_are_declared_as_such(self):
        """KEV, eCrimeLabs and MISP CERT-FR only ever grow.

        MISP CERT-FR was verified rather than assumed: its MISP manifest holds 18
        events spanning 2020-2024 and the hashes CSV carries no date column.
        """
        from app.feeds.base import FULL_LIST_CUMULATIVE
        from app.feeds.cisa_kev import CISAKEVFeed
        from app.feeds.ecrimelabs import ECrimeLabsCVEFeed
        from app.feeds.misp_cert_fr import MISPCertFRFeed

        for connector in (CISAKEVFeed, ECrimeLabsCVEFeed, MISPCertFRFeed):
            assert connector.full_list_kind == FULL_LIST_CUMULATIVE, connector.__name__

    def test_timestamped_connectors_declare_no_kind(self):
        from app.feeds.malwarebazaar import MalwareBazaarFeed
        from app.feeds.threatfox import ThreatFoxFeed
        from app.feeds.urlhaus import URLhausFeed

        for connector in (URLhausFeed, ThreatFoxFeed, MalwareBazaarFeed):
            assert connector.full_list_kind is None, connector.__name__

    def test_every_timestamp_free_connector_declares_WHICH_KIND(self):
        """The invariant. Declaring "full list" is not enough — it must say which.

        A connector supplying no timestamps and no kind falls through to the
        always-increment fallback, which is the inflation this fixes. Declaring the
        wrong kind is worse than not declaring: `current-state` on a cumulative
        catalogue pins recency at 100.0 permanently.
        """
        import importlib
        import inspect
        import pkgutil

        from app import feeds as feeds_pkg
        from app.feeds.base import FULL_LIST_KINDS, BaseFeed

        offenders = []
        for mod in pkgutil.iter_modules(feeds_pkg.__path__):
            module = importlib.import_module("app.feeds." + mod.name)
            for obj in vars(module).values():
                if not (isinstance(obj, type) and issubclass(obj, BaseFeed)
                        and obj is not BaseFeed):
                    continue
                src = inspect.getsource(obj)
                supplies_ts = "first_seen=" in src or "last_seen=" in src
                if not supplies_ts and obj.full_list_kind not in FULL_LIST_KINDS:
                    offenders.append((obj.__name__, obj.full_list_kind))
        assert not offenders, (
            "these connectors supply no per-record timestamps and do not declare a "
            "valid full_list_kind, so their sighting counters will inflate: "
            + repr(offenders)
        )

    def test_declared_kinds_are_valid_values(self):
        """A typo would silently fall through to the increment fallback."""
        import importlib
        import pkgutil

        from app import feeds as feeds_pkg
        from app.feeds.base import FULL_LIST_KINDS, BaseFeed

        for mod in pkgutil.iter_modules(feeds_pkg.__path__):
            module = importlib.import_module("app.feeds." + mod.name)
            for obj in vars(module).values():
                if isinstance(obj, type) and issubclass(obj, BaseFeed):
                    assert obj.full_list_kind is None or obj.full_list_kind in FULL_LIST_KINDS, (
                        obj.__name__ + " has full_list_kind=" + repr(obj.full_list_kind)
                    )

    async def test_a_current_state_list_freezes_the_counter_but_advances_last_seen(
        self, ingest
    ):
        """blocklist.de: presence re-asserts liveness."""
        from app.feeds.base import FULL_LIST_CURRENT_STATE

        run, make_feed, read, _add, _ids, _counter = ingest
        feed_id = await make_feed("blocklist-de")

        raw = _raw(31000, timestamped=False)
        raw["_full_list_kind"] = FULL_LIST_CURRENT_STATE

        await run(feed_id, [raw])
        first_seen_at = (await read(raw["value"])).last_seen
        for _ in range(5):
            await run(feed_id, [raw])

        row = await read(raw["value"])
        print("\n  current-state, 6 syncs -> sighting_count="
              + str(row.sighting_count) + ", last_seen advanced="
              + str(row.last_seen >= first_seen_at))
        assert row.sighting_count == 1, (
            "counter inflated to " + str(row.sighting_count)
        )
        assert row.last_seen >= first_seen_at, "last_seen must not go backwards"

    async def test_a_cumulative_catalogue_freezes_both(self, ingest):
        """CISA KEV: presence today is not an observation today.

        Advancing `last_seen` here would pin `_recency_score` at its 100.0 ceiling
        forever, so every KEV CVE would hold its day-0 score permanently — undoing
        the monotone-non-increasing trajectory the cve weight profile depends on.
        """
        from app.feeds.base import FULL_LIST_CUMULATIVE

        run, make_feed, read, _add, _ids, counter = ingest
        feed_id = await make_feed("cisa-kev")

        raw = _raw(31500, timestamped=False)
        raw["_full_list_kind"] = FULL_LIST_CUMULATIVE

        await run(feed_id, [raw])
        original = await read(raw["value"])
        original_last_seen = original.last_seen

        counter.reset()
        for _ in range(5):
            await run(feed_id, [raw])

        row = await read(raw["value"])
        updates = counter.matching("update iocs")
        print("\n  cumulative, 5 re-syncs -> sighting_count=" + str(row.sighting_count)
              + ", last_seen frozen=" + str(row.last_seen == original_last_seen)
              + ", UPDATEs=" + str(len(updates)))

        assert row.sighting_count == 1
        assert row.last_seen == original_last_seen, (
            "last_seen advanced for a cumulative catalogue — recency would be pinned "
            "at 100.0 forever and the CVE decay trajectory would disappear"
        )
        # Bonus: nothing changed, so cumulative feeds are also free to re-read.
        assert len(updates) == 0, (
            "cumulative re-reads should be skipped entirely\n" + counter.summary()
        )

    async def test_recency_still_decays_for_a_cumulative_catalogue(self, ingest):
        """The property the freeze protects, asserted through the score.

        A cumulative entry whose `last_seen` is held at its original value scores
        strictly lower than the same entry dated today — which is what makes the
        measured KEV trajectory decay rather than sit flat.
        """
        from datetime import timedelta as td

        from app.feeds.base import FULL_LIST_CUMULATIVE
        from app.services.scoring_engine import _recency_score

        run, make_feed, read, _add, _ids, _counter = ingest
        feed_id = await make_feed("cisa-kev-decay")

        raw = _raw(31600, timestamped=False)
        raw["_full_list_kind"] = FULL_LIST_CUMULATIVE
        await run(feed_id, [raw])
        for _ in range(3):
            await run(feed_id, [raw])

        row = await read(raw["value"])
        aged = row.last_seen - td(days=45)
        print("\n  recency at stored last_seen : " + str(_recency_score(row.last_seen)))
        print("  recency 45 days older        : " + str(_recency_score(aged)))
        assert _recency_score(aged) < _recency_score(row.last_seen), (
            "recency is not decaying with age — the term is inert"
        )


class TestDatetimeNormalisation:
    """MySQL DATETIME(0) rounds; the code truncates. Both sides must agree.

    With normalisation on one side only, the re-read gate compared a rounded stored
    value against an unrounded source value and fired based on the microsecond
    fraction — roughly 50/50, silently.
    """

    def test_producers_emit_whole_seconds(self):
        from app.services.feed_ingestion import _now, _strip_tz

        assert _now().microsecond == 0
        assert _now().tzinfo is None

        aware = datetime(2026, 7, 30, 12, 0, 0, 837451, tzinfo=timezone.utc)
        stripped = _strip_tz(aware)
        assert stripped.tzinfo is None
        assert stripped.microsecond == 0
        # Truncation, not rounding — a normalised value is never LATER than the
        # instant it represents, so "has the source advanced" cannot answer yes
        # spuriously.
        assert stripped.second == 0
        assert _strip_tz(None) is None

    async def test_a_written_timestamp_round_trips_unchanged(self, ingest):
        """The property that makes the gate deterministic: stored == written."""
        run, make_feed, read, _add, _ids, _counter = ingest
        feed_id = await make_feed("urlhaus-roundtrip")

        # .837451 rounds UP in MySQL, so an untruncated write would come back one
        # second later than it was written.
        raw = _raw(32000)
        raw["last_seen"] = raw["last_seen"].replace(microsecond=837451)
        raw["first_seen"] = raw["first_seen"].replace(microsecond=837451)

        await run(feed_id, [raw])
        stored = (await read(raw["value"])).last_seen
        expected = raw["last_seen"].replace(tzinfo=None, microsecond=0)

        print("\n  source " + str(raw["last_seen"]))
        print("  stored " + str(stored))
        print("  expect " + str(expected))
        assert stored == expected, (
            "the stored value differs from the normalised source value, so the "
            "re-read gate compares against a different number than it wrote"
        )

    async def test_the_gate_is_deterministic_across_awkward_fractions(self, ingest):
        """The regression guard for the 50/50 gate.

        Sweeps microsecond fractions either side of MySQL's rounding boundary. Every
        one must read as unchanged on re-read; before normalisation, fractions above
        .5 rounded up on write and then compared as an advance.
        """
        run, make_feed, read, _add, _ids, counter = ingest
        feed_id = await make_feed("urlhaus-fractions")

        fractions = (0, 1, 400000, 499999, 500000, 500001, 837451, 999999)
        for i, micro in enumerate(fractions):
            raw = _raw(33000 + i)
            raw["last_seen"] = raw["last_seen"].replace(microsecond=micro)
            raw["first_seen"] = raw["first_seen"].replace(microsecond=micro)
            await run(feed_id, [raw])

            counter.reset()
            await run(feed_id, [raw])          # identical re-read
            updates = counter.matching("update iocs")
            row = await read(raw["value"])
            assert len(updates) == 0, (
                "microsecond=" + str(micro) + " produced a write on an unchanged "
                "re-read — the gate is fraction-dependent again"
            )
            assert row.sighting_count == 1, (
                "microsecond=" + str(micro) + " inflated the counter"
            )
        print("\n  gate deterministic across " + str(len(fractions)) + " fractions")
