"""`NaiveUTCDateTime` — the type that makes the naive-UTC convention enforced.

Two tiers. The unit tests here need no database and pin the coercion contract
directly. The MySQL-marked tests at the bottom pin the property the whole design
rests on — that coercion fires on **comparison operands**, not only on inserts —
which a mocked session structurally cannot demonstrate, since it is the bind-parameter
machinery under test.
"""

from datetime import datetime, timedelta, timezone

import pytest
import sqlalchemy as sa

from app.models.types import NaiveUTCDateTime, utcnow

IST = timezone(timedelta(hours=5, minutes=30))


class TestBindCoercion:
    """`process_bind_param` in isolation."""

    def _bind(self, value):
        return NaiveUTCDateTime().process_bind_param(value, None)

    def test_an_aware_ist_value_becomes_the_equivalent_naive_utc(self):
        """The measured failure: the offset used to be discarded, not applied.

        `12:00+05:30` is `06:30Z`. Without coercion MySQL stores the wall-clock
        reading `12:00`, a 5.5-hour error with no warning.
        """
        aware = datetime(2026, 7, 30, 12, 0, tzinfo=IST)
        assert self._bind(aware) == datetime(2026, 7, 30, 6, 30)
        assert self._bind(aware).tzinfo is None

    def test_an_aware_utc_value_is_unchanged_but_stripped(self):
        aware = datetime(2026, 7, 30, 12, 0, tzinfo=timezone.utc)
        assert self._bind(aware) == datetime(2026, 7, 30, 12, 0)
        assert self._bind(aware).tzinfo is None

    def test_a_naive_value_passes_through_untouched(self):
        """Naive is the stored convention, so it must not be reinterpreted."""
        naive = datetime(2026, 7, 30, 12, 0)
        assert self._bind(naive) is naive

    def test_none_passes_through(self):
        assert self._bind(None) is None

    def test_a_negative_offset_coerces_in_the_other_direction(self):
        aware = datetime(2026, 7, 30, 2, 0, tzinfo=timezone(timedelta(hours=-5)))
        assert self._bind(aware) == datetime(2026, 7, 30, 7, 0)

    def test_reads_are_not_coerced(self):
        """No `process_result_value`, deliberately.

        `to_ist_str()` assumes naive input and `test_mysql_integration.py` pins naive
        reads, so returning aware values would be a wider behavioural change than this
        work intends. Asserted rather than left to inspection, because adding the hook
        later would silently alter every read path.
        """
        assert type(NaiveUTCDateTime()).process_result_value is \
            sa.types.TypeDecorator.process_result_value, (
            "a process_result_value override was added — reads are supposed to stay "
            "naive; see the class docstring and Spec 5 §5 condition 3"
        )

    def test_cache_ok_is_set(self):
        """Its absence is a per-query warning, not an error — easy to miss in review."""
        assert NaiveUTCDateTime.cache_ok is True


class TestUtcnowHelper:
    def test_it_is_naive_and_whole_seconds(self):
        """MySQL DATETIME(0) *rounds* fractional seconds, so truncating on write is
        what keeps a comparison predicate deterministic — see §8 item 0e."""
        now = utcnow()
        assert now.tzinfo is None
        assert now.microsecond == 0


class TestEveryModelColumnUsesIt:
    """The point of the exercise: no `DateTime` column may be left unprotected.

    Extraction verified by mutation — reverting a single column to `sa.DateTime` makes
    this fail. Without that check the test would pass vacuously if the reflection ever
    stopped finding columns.
    """

    @staticmethod
    def _datetime_columns():
        import app.models  # noqa: F401  - registers every mapper
        from app.database import Base

        found = []
        for table in Base.metadata.tables.values():
            for column in table.columns:
                if isinstance(column.type, (sa.DateTime, NaiveUTCDateTime)):
                    found.append((table.name, column.name, column.type))
        return found

    def test_the_reflection_finds_columns_at_all(self):
        """Guards the extraction, not the assertion."""
        columns = self._datetime_columns()
        assert len(columns) >= 14, (
            f"only {len(columns)} datetime columns discovered — the reflection is not "
            "seeing the models, so the assertion below would pass vacuously"
        )

    def test_every_datetime_column_is_a_naive_utc_datetime(self):
        unprotected = [
            f"{table}.{column}"
            for table, column, type_ in self._datetime_columns()
            if not isinstance(type_, NaiveUTCDateTime)
        ]
        assert not unprotected, (
            "these columns still use a bare DateTime, so an aware value written to or "
            "compared against them has its offset silently discarded: "
            + repr(unprotected)
        )

    def test_the_type_does_not_change_the_emitted_ddl(self):
        """It is a boundary coercion, not a schema change — no migration is implied."""
        from sqlalchemy.dialects import mysql

        plain = sa.DateTime().compile(dialect=mysql.dialect())
        decorated = NaiveUTCDateTime().compile(dialect=mysql.dialect())
        assert plain == decorated == "DATETIME"


@pytest.mark.mysql
class TestCoercionAgainstRealMySQL:
    """The property the design rests on, against the real driver.

    A mocked session cannot show this: the bind-parameter machinery *is* the thing
    under test, and the pre-fix behaviour was a silently wrong row set rather than an
    exception.
    """

    def test_it_fires_on_a_comparison_operand_not_only_on_insert(self, mysql_session):
        """The open question from the design note, pinned.

        Two rows at the same instant expressed differently; then a filter with an
        IST-aware boundary. Coerced gives 2, uncoerced gives 1 — and uncoerced raises
        nothing, which is why this needs asserting rather than trusting.
        """
        table = sa.Table(
            "tz_probe", sa.MetaData(),
            sa.Column("id", sa.Integer, primary_key=True),
            sa.Column("ts", NaiveUTCDateTime),
        )
        engine = mysql_session.get_bind()
        table.drop(engine, checkfirst=True)
        table.create(engine)
        try:
            with engine.begin() as conn:
                conn.execute(table.insert(), [
                    {"id": 1, "ts": datetime(2026, 7, 30, 12, 0)},
                    {"id": 2, "ts": datetime(2026, 7, 30, 12, 0, tzinfo=IST)},
                ])

            with engine.connect() as conn:
                stored = dict(conn.execute(
                    sa.select(table.c.id, table.c.ts).order_by(table.c.id)).all())
                # Insert coercion: the aware IST value landed as its UTC equivalent.
                assert stored[1] == datetime(2026, 7, 30, 12, 0)
                assert stored[2] == datetime(2026, 7, 30, 6, 30)

                # Comparison coercion: 09:00+05:30 is 03:30Z, which is before BOTH rows.
                boundary = datetime(2026, 7, 30, 9, 0, tzinfo=IST)
                count = conn.execute(sa.select(sa.func.count()).select_from(table)
                                     .where(table.c.ts > boundary)).scalar()
                assert count == 2, (
                    f"got {count}; 2 means the boundary was coerced to 03:30Z, 1 means "
                    "the offset was discarded and it was compared as 09:00"
                )

                # Reads stay naive.
                assert stored[2].tzinfo is None
        finally:
            table.drop(engine, checkfirst=True)

    def test_raw_text_sql_is_still_not_covered(self, mysql_session):
        """The documented gap, asserted so it cannot be forgotten.

        No column type is in play for `sa.text()`, so the value goes straight to the
        driver and the offset is discarded. `scripts/rescore_corpus.py` is built
        entirely on `text()`; it passes no datetimes today but is one edit away. This
        test failing would mean the gap closed — good news, but the CLAUDE.md caution
        and this docstring should then be updated together.
        """
        table = sa.Table(
            "tz_probe_raw", sa.MetaData(),
            sa.Column("id", sa.Integer, primary_key=True),
            sa.Column("ts", NaiveUTCDateTime),
        )
        engine = mysql_session.get_bind()
        table.drop(engine, checkfirst=True)
        table.create(engine)
        try:
            with engine.begin() as conn:
                conn.execute(table.insert(),
                             [{"id": 1, "ts": datetime(2026, 7, 30, 12, 0)}])

            with engine.connect() as conn:
                # 14:00+05:30 is 08:30Z, which is before the row; coerced -> 1.
                boundary = datetime(2026, 7, 30, 14, 0, tzinfo=IST)
                count = conn.execute(
                    sa.text("SELECT COUNT(*) FROM tz_probe_raw WHERE ts > :b"),
                    {"b": boundary},
                ).scalar()
                assert count == 0, (
                    f"got {count}. 0 is the documented gap — text() bypasses the "
                    "decorator, so 14:00+05:30 was compared as 14:00 wall-clock. If "
                    "this is now 1, raw SQL is covered and the CLAUDE.md caution can "
                    "be narrowed."
                )
        finally:
            table.drop(engine, checkfirst=True)
