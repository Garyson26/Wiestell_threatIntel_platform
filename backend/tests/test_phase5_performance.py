"""Phase 5 performance work: the parts that are assertable without a database.

The statement-count ceilings live in `tests/test_query_budget.py` and need the MySQL
container. What is pinned here is the *shape* of the fixes  -  that the aggregation helper
counts correctly, that concurrency is actually bounded, and that the pool is sized for
the deployment that exists rather than for an imagined one.
"""

import asyncio

import pytest


class TestTechniqueCountAggregation:
    """`attack.py::_technique_ioc_counts` replaced a COUNT per technique.

    The rewrite has to reproduce the old semantics exactly, and the interesting case is
    the one a `COUNT ... WHERE json_contains` handled implicitly: an IOC whose array
    repeats a technique counted once, not twice.
    """

    @staticmethod
    def _count(rows):
        """Drive the helper's aggregation over given `mitre_techniques` values."""
        from collections import Counter

        counts: Counter = Counter()
        for techniques in rows:
            if isinstance(techniques, str):
                import json
                try:
                    techniques = json.loads(techniques)
                except (ValueError, TypeError):
                    continue
            if not isinstance(techniques, (list, tuple)):
                continue
            counts.update({t for t in techniques if isinstance(t, str)})
        return counts

    def test_an_ioc_counts_once_per_technique(self):
        counts = self._count([["T1071", "T1071"], ["T1071"]])
        assert counts["T1071"] == 2, (
            "a repeated technique in one IOC's array was counted twice; "
            "COUNT ... WHERE json_contains counted the row once"
        )

    def test_multiple_techniques_on_one_ioc_all_count(self):
        counts = self._count([["T1071", "T1190"]])
        assert counts["T1071"] == 1 and counts["T1190"] == 1

    def test_malformed_arrays_are_skipped_not_raised(self):
        """`mitre_techniques` is JSON written by feed connectors  -  untrusted shape."""
        counts = self._count([None, "not json", 7, {"a": 1}, [], [None, 5], ["T1071"]])
        assert counts == {"T1071": 1}

    def test_a_raw_json_string_is_parsed(self):
        """Defensive path for a driver handing back unparsed JSON."""
        assert self._count(['["T1071"]'])["T1071"] == 1

    def test_the_helper_exists_and_is_used_by_both_endpoints(self):
        """Guards the wiring: a per-technique COUNT must not come back."""
        import inspect

        from app.api import attack

        assert hasattr(attack, "_technique_ioc_counts")
        for name in ("get_attack_matrix", "get_heatmap"):
            source = inspect.getsource(getattr(attack, name))
            assert "_technique_ioc_counts" in source, f"{name} bypasses the helper"
            assert "func.count(IOC.id)" not in source, (
                f"{name} contains a per-technique COUNT again"
            )


class TestTrendsAggregation:
    """`dashboard.py::get_trends` was 2 queries per day requested."""

    def test_it_no_longer_loops_queries(self):
        import inspect

        from app.api import dashboard

        source = inspect.getsource(dashboard.get_trends)
        assert "group_by" in source, "get_trends is not grouping in SQL"
        # The old shape: an await inside the per-day loop.
        loop_body = source.split("for i in range(days)")[-1]
        assert "await" not in loop_body, (
            "get_trends awaits inside the per-day loop again, so the statement count is "
            "proportional to `days` (which reaches 90)"
        )

    def test_the_utc_day_semantics_are_preserved(self):
        """Deliberately UTC, not IST. Changing this is a product decision, not a rewrite.

        Audited 2026-07-31: the previous implementation bucketed and labelled by UTC day
        consistently, nothing in the UI labels these buckets, and `/trends` has no
        frontend caller, so the rewrite was required to preserve behaviour exactly.

        Checked against the *code* rather than the raw source: the first version of this
        test grepped the text and failed on its own docstring, which names the very
        expressions it forbids. Comments and the docstring are stripped first.
        """
        import ast
        import inspect
        import textwrap

        from app.api import dashboard

        tree = ast.parse(textwrap.dedent(inspect.getsource(dashboard.get_trends)))
        function = tree.body[0]
        # Drop the docstring so its prose is not searched as if it were code.
        if (function.body and isinstance(function.body[0], ast.Expr)
                and isinstance(function.body[0].value, ast.Constant)
                and isinstance(function.body[0].value.value, str)):
            function.body = function.body[1:]
        code = ast.unparse(function)   # comments are absent from an AST by construction

        for forbidden in ("CONVERT_TZ", "INTERVAL 330", "convert_tz"):
            assert forbidden not in code, (
                f"{forbidden} appeared in get_trends. Shifting the bucket timezone is a "
                "product decision that also changes what the labels mean  -  see the "
                "CLAUDE.md caution, and note CONVERT_TZ with a zone *name* returns NULL "
                "silently when the MySQL timezone tables are absent, collapsing every "
                "bucket into one NULL group."
            )
        assert "timezone.utc" in code, "the UTC anchor is gone from get_trends"


class TestEnrichmentConcurrencyIsBounded:
    """Unbounded `asyncio.gather` across a 50,000-IOC backfill on 0.1 CPU."""

    def test_the_ceiling_exists_and_is_small(self):
        from app.services import enrichment_engine

        assert enrichment_engine.ENRICHMENT_CONCURRENCY <= 10, (
            "the enrichment concurrency ceiling was raised above 10; NVD without a key "
            "allows 5 requests per 30s, so parallelism converts into 429s"
        )

    def test_the_semaphore_is_process_wide_not_per_call(self):
        """A per-call semaphore caps fan-out within one IOC and not across a backfill.

        The backfill is the case that needs the bound, so the object has to be shared.
        """
        from app.services import enrichment_engine

        assert isinstance(enrichment_engine._enrichment_semaphore, asyncio.Semaphore)
        assert enrichment_engine._enrichment_semaphore._value == \
            enrichment_engine.ENRICHMENT_CONCURRENCY

    def test_it_actually_limits_in_flight_work(self, monkeypatch):
        """Measured rather than asserted structurally.

        Runs more tasks than the ceiling through the wrapper and records the peak
        overlap. Without the semaphore the peak equals the task count.
        """
        from app.services import enrichment_engine

        in_flight = 0
        peak = 0

        async def _fake_enricher(source, ioc):
            nonlocal in_flight, peak
            in_flight += 1
            peak = max(peak, in_flight)
            await asyncio.sleep(0.01)
            in_flight -= 1
            return {"source": source, "data": {}}

        monkeypatch.setattr(enrichment_engine, "_run_enricher", _fake_enricher)

        async def _drive():
            tasks = [
                enrichment_engine._run_enricher_bounded(f"s{i}", None)
                for i in range(20)
            ]
            await asyncio.gather(*tasks)

        asyncio.run(_drive())
        assert peak <= enrichment_engine.ENRICHMENT_CONCURRENCY, (
            f"peak overlap {peak} exceeded the ceiling of "
            f"{enrichment_engine.ENRICHMENT_CONCURRENCY}"
        )
        assert peak > 1, "nothing ran concurrently, so the measurement proves nothing"

    def test_the_gather_call_site_uses_the_bounded_wrapper(self):
        import inspect

        from app.services import enrichment_engine

        source = inspect.getsource(enrichment_engine.enrich_ioc)
        assert "_run_enricher_bounded" in source
        assert "_run_enricher(s, ioc)" not in source, (
            "enrich_ioc gathers the unbounded enricher again"
        )


class TestPoolIsSizedForTheRealDeployment:
    """30 connections per process against a shared MySQL account allowance."""

    def test_the_async_pool_is_small(self):
        """Asserted against the live engine, not the source text.

        The first version of this test grepped for `pool_size=10` and failed on the
        comment that *explains* the resize  -  a source-text assertion cannot distinguish
        code from the prose describing it. Reading the pool object is both stricter and
        immune to that.
        """
        from app.database import async_engine

        pool = async_engine.pool
        total = pool.size() + pool._max_overflow
        assert pool.size() == 2, f"pool_size is {pool.size()}"
        assert pool._max_overflow == 3, f"max_overflow is {pool._max_overflow}"
        assert total <= 5, (
            f"the async pool allows {total} connections per process. Hostinger shared "
            "MySQL commonly permits 25-75 for the whole ACCOUNT, not per application, "
            "and Render may run several instances each with its own pool"
        )

    def test_the_sync_and_async_pools_are_comparable(self):
        """Both draw on the same account allowance, so one must not dwarf the other."""
        from app.database import async_engine, sync_engine

        async_total = async_engine.pool.size() + async_engine.pool._max_overflow
        sync_total = sync_engine.pool.size() + sync_engine.pool._max_overflow
        assert abs(async_total - sync_total) <= 3, (
            f"async allows {async_total} and sync {sync_total}; they share one shared-host "
            "connection budget, so a large gap means one path can starve the other"
        )

    def test_pool_recycle_still_precedes_the_wait_timeout(self):
        """Easy to break while editing next to the sizing.

        280 s must stay under the shared host's 300 s `wait_timeout`, or the server closes
        pooled connections first and the client discovers it as an OperationalError
        mid-request. This is the failure the `aiomysql.ensure_closed` patch exists to
        soften; the recycle window is what prevents it.
        """
        from app.database import async_engine, sync_engine

        for engine in (async_engine, sync_engine):
            assert engine.pool._recycle == 280, (
                f"pool_recycle is {engine.pool._recycle}, not 280"
            )


class TestHeavyDependenciesAreUnused:
    """`pandas` and `weasyprint` are declared and never imported.

    The Phase 5 item was "lazy pandas and weasyprint imports", but there is nothing to
    make lazy: neither package is imported anywhere in the codebase, and nothing generates
    a PDF. So the actionable form is removal from requirements.txt, which is an owner
    decision (weasyprint is presumably a placeholder for planned PDF export).

    This test fails if either is ever imported, which is the moment the lazy-import
    question becomes real rather than void.
    """

    def test_neither_is_imported_anywhere(self):
        import pathlib
        import re

        root = pathlib.Path(__file__).resolve().parents[1]
        offenders = []
        for path in list((root / "app").rglob("*.py")):
            text = path.read_text(encoding="utf-8")
            for pattern in (r"^\s*import\s+pandas", r"^\s*from\s+pandas",
                            r"^\s*import\s+weasyprint", r"^\s*from\s+weasyprint"):
                if re.search(pattern, text, re.M):
                    offenders.append(f"{path.relative_to(root)}: {pattern}")
        assert not offenders, (
            "pandas or weasyprint is now imported: " + repr(offenders)
            + ". Both are heavy (pandas pulls numpy; weasyprint pulls cairo/pango) and "
            "this runs on a 512 MB instance, so the import belongs inside the function "
            "that needs it rather than at module scope."
        )

    @pytest.mark.parametrize("package", ["pandas", "weasyprint"])
    def test_they_are_still_declared(self, package):
        """So the test above cannot pass merely because they were quietly dropped."""
        import pathlib

        root = pathlib.Path(__file__).resolve().parents[1]
        requirements = (root / "requirements.txt").read_text(encoding="utf-8")
        if package not in requirements:
            pytest.skip(
                f"{package} has been removed from requirements.txt  -  if that was "
                "deliberate, delete this parametrised case"
            )
