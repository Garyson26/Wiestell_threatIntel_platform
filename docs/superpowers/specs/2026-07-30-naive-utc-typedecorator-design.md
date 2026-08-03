# Design Note — `NaiveUTCDateTime` TypeDecorator

**Date:** 2026-07-30
**Status:** **IMPLEMENTED 2026-07-31** (Spec 5 §5). `app/models/types.py::NaiveUTCDateTime`,
applied to all 18 `DateTime` columns; pinned by `tests/test_naive_utc_type.py`. The raw
`sa.text()` gap in §4 remains open by design and stays covered by the CLAUDE.md caution.
**Verdict:** viable. It fires on comparison operands, not only inserts — so it does
solve the filter problem. One real gap: raw `text()` SQL.

---

## 1. The problem it would replace

The [aware-datetime audit](../../../CLAUDE.md) found six sites where a
timezone-aware value reaches the database, every one correct **only because UTC's
offset is zero**. There is no defence in code; the convention is documentation plus
a caution comment.

Measured failure modes, both silent:

| Path | Aware input | Result |
|---|---|---|
| comparison | `11:00+05:30` vs a naive column | offset discarded, compared as `11:00` |
| insertion | `12:00+05:30` written to a naive column | stored as `12:00`, not `06:30` |

No exception, no warning, in either direction. The Phase 5 rewrite of
`dashboard.py::get_trends` into a `GROUP BY` has to compute day boundaries, and this
platform renders IST — so an IST-aware boundary would silently start each "day" at
18:30 the previous evening.

## 2. The proposal

```python
class NaiveUTCDateTime(types.TypeDecorator):
    """DATETIME that normalises aware values to naive UTC at the boundary."""
    impl = sa.DateTime
    cache_ok = True          # required, else SQLAlchemy warns per query

    def process_bind_param(self, value, dialect):
        if value is not None and value.tzinfo is not None:
            value = value.astimezone(timezone.utc).replace(tzinfo=None)
        return value
```

Applied to every `DateTime` column in `app/models/`, all six audited sites become
correct by construction and the IST trap becomes unreachable through the ORM.

## 3. Verification — does it fire on comparison operands?

**Yes.** This was the open question and it is settled empirically against MySQL 8.0.46
in the local container.

Two rows, `12:00` naive and `12:00+05:30` (= `06:30Z`). Insert coerced correctly:

```
id=1 stored 2026-07-30 12:00:00
id=2 stored 2026-07-30 06:30:00     <- aware IST coerced to UTC
```

Then a filter with an IST-aware boundary of `09:00+05:30` (= `03:30Z`):

```
B) FILTER path — process_bind_param fired? YES
   rows with ts > 09:00+05:30 (=03:30Z): 2
   correct answer if coerced  : 2
   answer if NOT coerced      : 1
```

It returned **2** — the coerced answer. `process_bind_param` received the aware
value and normalised it before binding. Because the hook is per bind parameter, it
also covers `IN`, `BETWEEN` and `case()` operands, which are the shapes
`dashboard.py::get_stats` and a future `GROUP BY` would use.

## 4. The gap: raw `text()` SQL

**The decorator does not fire for `sa.text()` with bound parameters.** There is no
column type in play, so the value goes straight to the driver:

```
raw text() SQL — decorator fired? NO
   boundary 14:00+05:30 (=08:30Z) -> count=0   | coerced=1, wall-clock=0
```

The result is **0** where a coerced comparison gives 1 — the exact silent wrong
answer the decorator exists to prevent, still reachable.

This matters here specifically: **`scripts/rescore_corpus.py` is built entirely on
`text()`**, and it is the one component that rewrites every score in the database.
It currently passes no datetimes as parameters — it reads `last_seen` out and hands
it to the scoring engine — so it is unaffected today. But it is one edit from being
affected, and a decorator gives a false sense that the class of bug is closed.

Other raw-SQL sites to check before adopting: the `information_schema` probe in
`rescore_corpus.py` (no datetimes), and `tests/conftest_mysql.py`'s TRUNCATE loop
(no datetimes).

## 5. Recommendation

Adopt, with three conditions:

1. **Keep the CLAUDE.md caution.** It remains the only control for raw `text()`.
   Reword it from "the convention is X" to "the ORM enforces X; raw `text()` does
   not" once the decorator lands.
2. **Do not change stored data.** The decorator only affects values crossing the
   boundary from Python. Every existing row is already naive UTC and must stay
   untouched — this is not a migration.
3. **Add a `process_result_value`? No.** Returning aware values would be a wider
   behavioural change: `tests/test_mysql_integration.py` pins that reads come back
   naive, and `to_ist_str()` assumes naive input. Leave reads alone; coerce writes
   and comparisons only.

Worth considering alongside: a `cache_ok = True` omission produces a per-query
SQLAlchemy warning rather than an error, so it is easy to miss in review.

## 6. Sequencing

Independent of the migration-chain repair, and safe to land before or after it.
Should land **before** Phase 5 rewrites `get_trends`, since the whole point is to
make that rewrite's day-boundary arithmetic safe by construction.

Does **not** change any stored score, so it does not interact with
`rescore_corpus.py`'s run ordering.
