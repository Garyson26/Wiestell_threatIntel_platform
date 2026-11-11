"""A tiny in-memory AsyncSession that actually evaluates WHERE clauses.

``conftest.FakeSession`` returns one configured object for every query, which is
fine for authorization tests (they resolve before the handler body runs) but
useless for account-security flows: a clash check would always "find" the caller,
and a lookup scoped to the wrong user would still return a row. Those are exactly
the bugs these flows must not have, so they need a fake that can say "no".

It also has real commit/rollback semantics: ``rollback()`` restores the state of
the last ``commit()``. ``get_db`` rolls back when a handler raises, so a counter
that is incremented but not committed before a 401 is silently lost — a bug a
no-op rollback could never show. Use :func:`dependency` to get a ``get_db``
override with the same commit-on-return / rollback-on-raise shape.

Supports the subset of SQLAlchemy the users API uses: ``select(Model)`` and
``update(Model)`` with ``== != < <= > >= in_ is_`` combined by ``&`` / ``|``,
``order_by(col.desc())``, and ``add`` / ``delete`` / ``flush`` / ``commit`` /
``rollback`` / ``refresh``. Anything else raises, so an unsupported query fails
loudly instead of matching everything.
"""

import itertools
import operator
import uuid
from datetime import datetime, timedelta

from sqlalchemy.sql import operators
from sqlalchemy.sql.dml import Update
from sqlalchemy.sql.elements import (
    BinaryExpression, BindParameter, BooleanClauseList, Grouping, Null,
)

_tick = itertools.count()

_COMPARE = {
    operators.eq: operator.eq,
    operators.ne: operator.ne,
    operators.lt: operator.lt,
    operators.le: operator.le,
    operators.gt: operator.gt,
    operators.ge: operator.ge,
}


def _value(node):
    if isinstance(node, BindParameter):
        return node.effective_value
    if isinstance(node, Null):
        return None
    raise NotImplementedError(f"unsupported right-hand side: {node!r}")


def _matches(clause, obj) -> bool:
    if clause is None:
        return True
    if isinstance(clause, Grouping):  # parenthesised `a | b` inside an AND
        return _matches(clause.element, obj)
    if isinstance(clause, BooleanClauseList):
        results = [_matches(c, obj) for c in clause.clauses]
        if clause.operator is operators.and_:
            return all(results)
        if clause.operator is operators.or_:
            return any(results)
        raise NotImplementedError(f"unsupported boolean operator: {clause.operator}")
    if isinstance(clause, BinaryExpression):
        actual = getattr(obj, clause.left.key)
        expected = _value(clause.right)
        op = clause.operator
        if op is operators.is_:
            return actual is expected
        if op is operators.is_not:
            return actual is not expected
        if op is operators.in_op:
            return actual in expected
        if op in _COMPARE:
            # SQL semantics: any comparison with NULL is not true.
            if actual is None or expected is None:
                return False
            return _COMPARE[op](actual, expected)
        raise NotImplementedError(f"unsupported comparison: {op}")
    raise NotImplementedError(f"unsupported clause: {type(clause).__name__}")


class _Result:
    def __init__(self, rows, rowcount=None):
        self._rows = rows
        self.rowcount = len(rows) if rowcount is None else rowcount

    def scalars(self):
        return self

    def all(self):
        return list(self._rows)

    def first(self):
        return self._rows[0] if self._rows else None

    def scalar_one_or_none(self):
        if len(self._rows) > 1:
            raise AssertionError(f"scalar_one_or_none() saw {len(self._rows)} rows")
        return self.first()


def _columns(obj):
    return [c.key for c in obj.__table__.columns]


class InMemorySession:
    def __init__(self, *objects):
        self.objects = []
        for obj in objects:
            self.add(obj)
        self.commits = 0
        self.rollbacks = 0
        self._snapshot = self._take_snapshot()

    # ── state ──
    def _take_snapshot(self):
        return [(obj, {k: getattr(obj, k) for k in _columns(obj)}) for obj in self.objects]

    def add(self, obj):
        # Python-side column defaults only fire at flush on a real session; apply the
        # two that handlers read back before any flush.
        if getattr(obj, "id", None) is None:
            obj.id = str(uuid.uuid4())
        if hasattr(obj, "created_at") and obj.created_at is None:
            obj.created_at = datetime(2026, 1, 1) + timedelta(microseconds=next(_tick))
        if obj not in self.objects:
            self.objects.append(obj)

    def of(self, model):
        return [o for o in self.objects if isinstance(o, model)]

    # ── statements ──
    async def execute(self, stmt, *args, **kwargs):
        if isinstance(stmt, Update):
            return self._update(stmt)
        model = stmt.column_descriptions[0]["entity"]
        rows = [o for o in self.of(model) if _matches(stmt.whereclause, o)]
        for clause in reversed(stmt._order_by_clauses):
            descending = getattr(clause, "modifier", None) is operators.desc_op
            column = clause.element if descending else clause
            rows.sort(key=lambda o: getattr(o, column.key), reverse=descending)
        return _Result(rows)

    def _update(self, stmt):
        model = stmt.table.entity_namespace if hasattr(stmt.table, "entity_namespace") else None
        targets = [o for o in self.objects
                   if o.__table__ is stmt.table and _matches(stmt.whereclause, o)]
        for obj in targets:
            for column, value in stmt._values.items():
                key = column if isinstance(column, str) else column.key
                setattr(obj, key, _value(value))
        del model
        return _Result(targets)

    async def delete(self, obj):
        self.objects.remove(obj)

    async def flush(self):
        pass

    async def commit(self):
        self.commits += 1
        self._snapshot = self._take_snapshot()

    async def rollback(self):
        self.rollbacks += 1
        self.objects = [obj for obj, _ in self._snapshot]
        for obj, values in self._snapshot:
            for key, value in values.items():
                setattr(obj, key, value)

    async def refresh(self, *args, **kwargs):
        pass


def dependency(db: InMemorySession):
    """A ``get_db`` override with the real one's shape: commit on return, roll back on raise."""

    async def _override():
        try:
            yield db
            await db.commit()
        except Exception:
            await db.rollback()
            raise

    return _override
