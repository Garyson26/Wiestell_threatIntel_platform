"""Chunking, statement budget and idempotence of scripts/rescore_corpus.py.

The script itself cannot be run here — it needs the Hostinger DSN — so this
exercises its driver against a fake session that records every statement. What
these tests actually protect:

* **Four statements per chunk, not thirty-one.** The naive shape fetches sources
  and enrichments per IOC, which is an N+1 across the public internet to a shared
  host. That is the pattern the rest of this work removes, so it must not be
  reintroduced here by a later edit.
* **`source_count` is distinct feeds, never the sighting count.** Getting this
  wrong would silently reintroduce the diversity bug the rescore exists to fix.
* **Keyset pagination and resumability**, since a run over the full corpus will
  be interrupted at some point.
"""

import importlib.util
import pathlib
import re

import pytest

_SCRIPT = (
    pathlib.Path(__file__).resolve().parents[2] / "scripts" / "rescore_corpus.py"
)


def _load_script():
    spec = importlib.util.spec_from_file_location("rescore_corpus", _SCRIPT)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


rescore_corpus = _load_script()


class _Result:
    def __init__(self, rows, dict_rows=None):
        self._rows = rows
        self._dict_rows = dict_rows

    def mappings(self):
        return _Result(self._dict_rows if self._dict_rows is not None else self._rows)

    def all(self):
        return self._rows

    def scalar(self):
        return self._rows[0][0] if self._rows else None


class FakeSession:
    """Records statements and serves canned corpus data.

    Mirrors the real schema closely enough that the driver's SQL shape matters:
    the chunk query is matched on ``FROM iocs``, the feed query on
    ``ioc_sources``, and so on. A driver that issued a per-IOC query would show up
    as extra recorded statements.
    """

    def __init__(self, iocs, sources=None, enrichments=None, has_override=False):
        self.iocs = sorted(iocs, key=lambda r: r["id"])
        self.sources = sources or {}          # ioc_id -> (feed_count, has_enabled)
        self.enrichments = enrichments or {}   # ioc_id -> [(source, data), ...]
        self.has_override = has_override
        self.statements = []
        self.writes = []
        self.commits = 0

    def execute(self, clause, params=None):
        sql = re.sub(r"\s+", " ", str(clause)).strip()
        self.statements.append(sql)
        params = params or {}

        if "information_schema.columns" in sql:
            return _Result([(1 if self.has_override else 0,)])

        if "FROM iocs" in sql and sql.startswith("SELECT"):
            last, limit = params["last_id"], params["limit"]
            rows = [r for r in self.iocs if r["id"] > last][:limit]
            if "manual_score_override IS NULL" in sql:
                rows = [r for r in rows if r.get("manual_score_override") is None]
            return _Result(rows, dict_rows=rows)

        if "ioc_sources" in sql:
            ids = params["ioc_ids"]
            return _Result([
                (i, self.sources[i][0], int(self.sources[i][1]))
                for i in ids if i in self.sources
            ])

        if "FROM enrichments" in sql:
            ids = params["ioc_ids"]
            out = []
            for i in ids:
                for source, data in self.enrichments.get(i, []):
                    out.append((i, source, data))
            return _Result(out)

        if sql.startswith("UPDATE iocs"):
            self.writes.append(list(params))
            return _Result([])

        raise AssertionError(f"unexpected statement: {sql}")

    def commit(self):
        self.commits += 1

    def rollback(self):
        pass

    def close(self):
        pass


def _ioc(idx, *, score=50, ioc_type="url", sightings=1, tags=None):
    return {
        "id": f"{idx:036d}",
        "type": ioc_type,
        "value": f"http://example.invalid/{idx}",
        "threat_score": score,
        "tags": tags if tags is not None else [],
        "metadata": {},
        "mitre_techniques": [],
        "last_seen": None,
        "sighting_count": sightings,
        "manual_score_override": None,
    }


def _run(session, **kwargs):
    kwargs.setdefault("chunk_size", 30)
    kwargs.setdefault("dry_run", False)
    kwargs.setdefault("verbose", False)
    rescorer = rescore_corpus.Rescorer(session, **kwargs)
    rescorer.run()
    return rescorer


class TestStatementBudget:
    def test_four_statements_per_chunk(self):
        """The headline constraint. 30 rows must cost 4 statements, not 31."""
        iocs = [_ioc(i) for i in range(30)]
        session = FakeSession(
            iocs,
            sources={r["id"]: (2, True) for r in iocs},
            enrichments={r["id"]: [("geoip", {"country_code": "RU"})] for r in iocs},
        )
        rescorer = _run(session)

        # 4 for the chunk + 1 terminal look-ahead. The look-ahead happens because
        # a full chunk cannot tell whether more rows follow, so it fetches once
        # more and gets nothing; it is a single indexed query at the very end of
        # the whole run, not per chunk.
        assert rescorer.statements == 5, session.statements
        assert rescorer.scanned == 30

        # The claim that matters: one statement of each kind for 30 rows.
        assert len([s for s in session.statements if "FROM iocs" in s]) == 2  # + look-ahead
        assert len([s for s in session.statements if "ioc_sources" in s]) == 1
        assert len([s for s in session.statements if "FROM enrichments" in s]) == 1
        assert len([s for s in session.statements if s.startswith("UPDATE")]) == 1

    def test_a_short_final_chunk_costs_no_look_ahead(self):
        """A partial chunk proves the end of the table, so 4 statements exactly."""
        iocs = [_ioc(i) for i in range(12)]
        session = FakeSession(
            iocs,
            sources={r["id"]: (2, True) for r in iocs},
            enrichments={r["id"]: [("geoip", {"country_code": "RU"})] for r in iocs},
        )
        rescorer = _run(session, chunk_size=30)
        assert rescorer.statements == 4, session.statements
        assert rescorer.scanned == 12

    def test_statement_count_scales_per_chunk_not_per_row(self):
        iocs = [_ioc(i) for i in range(90)]
        session = FakeSession(
            iocs,
            sources={r["id"]: (1, True) for r in iocs},
        )
        rescorer = _run(session, chunk_size=30)
        # 3 chunks x 4. Anything near 90 means an N+1 crept back in.
        assert rescorer.statements <= 3 * 4 + 1, rescorer.statements
        assert rescorer.scanned == 90

    def test_one_commit_per_chunk_not_one_transaction(self):
        """A single transaction over the whole table is the failure mode this
        script is shaped to avoid on a shared MySQL host."""
        iocs = [_ioc(i) for i in range(60)]
        session = FakeSession(iocs, sources={r["id"]: (1, True) for r in iocs})
        _run(session, chunk_size=30)
        assert session.commits == 2, session.commits

    def test_feed_count_and_enabled_flag_come_from_one_statement(self):
        iocs = [_ioc(i) for i in range(5)]
        session = FakeSession(iocs, sources={r["id"]: (3, True) for r in iocs})
        _run(session)
        feed_queries = [s for s in session.statements if "ioc_sources" in s]
        assert len(feed_queries) == 1
        sql = feed_queries[0]
        assert "COUNT(DISTINCT s.feed_id)" in sql
        assert "MAX(f.is_enabled)" in sql


class TestScoringInputs:
    def test_source_count_is_distinct_feeds_not_sightings(self):
        """An IOC with 100 sightings from 1 feed must score as 1 source."""
        one_feed = _ioc(1, sightings=100)
        session = FakeSession([one_feed], sources={one_feed["id"]: (1, True)})
        _run(session)
        written = session.writes[0][0]

        from app.services.scoring_engine import calculate_threat_score

        expected = calculate_threat_score(
            {
                "type": "url", "value": one_feed["value"], "tags": [],
                "mitre_techniques": [], "last_seen": None, "sighting_count": 100,
                "metadata": {},
            },
            source_count=1,
            enrichment_data=[],
            has_enabled_feed_source=True,
        )
        assert written["threat_score"] == expected

        # And the diversity term really is the 1-source floor, not the 5+ ceiling.
        from app.services.scoring_engine import _source_diversity_score

        assert _source_diversity_score(1) == 30.0

    def test_an_ioc_with_no_sources_still_scores(self):
        """Analyst-submitted indicators have no ioc_sources rows at all."""
        orphan = _ioc(1)
        session = FakeSession([orphan], sources={})
        rescorer = _run(session)
        assert rescorer.scanned == 1

    def test_enrichments_are_grouped_not_fetched_per_ioc(self):
        iocs = [_ioc(i) for i in range(4)]
        session = FakeSession(
            iocs,
            sources={r["id"]: (1, True) for r in iocs},
            enrichments={
                iocs[0]["id"]: [("geoip", {"country_code": "KP"}),
                                ("dns", {"fast_flux": True})],
                iocs[2]["id"]: [("geoip", {"country_code": "US"})],
            },
        )
        _run(session)
        assert len([s for s in session.statements if "FROM enrichments" in s]) == 1

    def test_json_columns_are_accepted_as_strings_or_objects(self):
        """MySQL JSON arrives parsed or raw depending on driver and version."""
        as_string = _ioc(1)
        as_string["tags"] = '["ransomware"]'
        as_string["metadata"] = "{}"
        session = FakeSession([as_string], sources={as_string["id"]: (1, True)})
        rescorer = _run(session)
        assert rescorer.scanned == 1

    def test_malformed_json_degrades_rather_than_aborting_the_run(self):
        bad = _ioc(1)
        bad["tags"] = "{not json"
        session = FakeSession([bad], sources={bad["id"]: (1, True)})
        rescorer = _run(session)
        assert rescorer.scanned == 1


class TestPaginationAndResume:
    def test_keyset_pagination_visits_every_row_once(self):
        iocs = [_ioc(i) for i in range(75)]
        session = FakeSession(iocs, sources={r["id"]: (1, True) for r in iocs})
        rescorer = _run(session, chunk_size=10)
        assert rescorer.scanned == 75
        assert rescorer.last_id == iocs[-1]["id"]

    def test_start_after_resumes_without_rescanning(self):
        iocs = [_ioc(i) for i in range(20)]
        session = FakeSession(iocs, sources={r["id"]: (1, True) for r in iocs})
        rescorer = rescore_corpus.Rescorer(
            session, chunk_size=10, dry_run=False, verbose=False
        )
        rescorer.run(start_after=iocs[9]["id"])
        assert rescorer.scanned == 10

    def test_empty_corpus_is_a_no_op(self):
        session = FakeSession([])
        rescorer = _run(session)
        assert rescorer.scanned == 0
        assert session.writes == []


class TestIdempotenceAndSafety:
    def test_second_run_writes_nothing(self):
        """Scoring is a pure function of evidence, so a converged run is a no-op."""
        iocs = [_ioc(i) for i in range(10)]
        sources = {r["id"]: (2, True) for r in iocs}
        first = FakeSession(iocs, sources=sources)
        _run(first)

        settled = []
        applied = {w["ioc_id"]: w["threat_score"] for batch in first.writes for w in batch}
        for row in iocs:
            updated = dict(row)
            updated["threat_score"] = applied.get(row["id"], row["threat_score"])
            settled.append(updated)

        second = FakeSession(settled, sources=sources)
        rescorer = _run(second)
        assert second.writes == [], rescorer.changed
        assert rescorer.changed == 0

    def test_dry_run_writes_nothing(self):
        iocs = [_ioc(i) for i in range(10)]
        session = FakeSession(iocs, sources={r["id"]: (1, True) for r in iocs})
        rescorer = _run(session, dry_run=True)
        assert session.writes == []
        assert session.commits == 0
        assert rescorer.scanned == 10

    def test_manual_overrides_are_skipped_when_the_column_exists(self):
        iocs = [_ioc(i) for i in range(4)]
        iocs[1]["manual_score_override"] = 90
        session = FakeSession(
            iocs,
            sources={r["id"]: (1, True) for r in iocs},
            has_override=True,
        )
        rescorer = _run(session)
        assert rescorer.scanned == 3
        chunk_sql = [s for s in session.statements if "FROM iocs" in s][0]
        assert "manual_score_override IS NULL" in chunk_sql

    def test_no_override_filter_before_the_column_exists(self):
        iocs = [_ioc(i) for i in range(3)]
        session = FakeSession(
            iocs, sources={r["id"]: (1, True) for r in iocs}, has_override=False
        )
        _run(session)
        chunk_sql = [s for s in session.statements if "FROM iocs" in s][0]
        assert "manual_score_override" not in chunk_sql

    def test_band_distribution_is_reported_for_both_sides(self):
        iocs = [_ioc(i, score=100) for i in range(5)]
        session = FakeSession(iocs, sources={r["id"]: (1, True) for r in iocs})
        rescorer = _run(session)
        assert sum(rescorer.before.values()) == 5
        assert sum(rescorer.after.values()) == 5
        assert rescorer.before["critical"] == 5

    def test_thresholds_are_the_published_ones(self):
        assert rescore_corpus.BANDS == ("critical", "high", "medium", "low")
        assert rescore_corpus.get_score_category(76) == "critical"
        assert rescore_corpus.get_score_category(51) == "high"
        assert rescore_corpus.get_score_category(26) == "medium"
        assert rescore_corpus.get_score_category(25) == "low"


class TestCLI:
    def test_chunk_size_must_be_positive(self):
        with pytest.raises(SystemExit):
            rescore_corpus.main(["--chunk-size", "0"])

    def test_default_chunk_size_matches_the_ingestion_path(self):
        """feed_ingestion holds locks for 30 rows at a time; so does this."""
        from app.services.feed_ingestion import _DEFAULT_BATCH_SIZE

        assert rescore_corpus.DEFAULT_CHUNK_SIZE == _DEFAULT_BATCH_SIZE


class TestIngestChunkStatementBudget:
    """Section 0.5 added one grouped SELECT per chunk. Measure it, don't assume it.

    The re-read path recomputes `threat_score` and until 2026-07-30 did so without
    `enrichment_data`, collapsing both the enrichment-risk term and the reputation
    term (which resolves the reputation payload *and*, for CVEs, the NVD CVSS score
    out of that same list) to their no-evidence defaults. Measured cost of one
    re-read on a fully enriched indicator: -23 for an IP or URL, -44 for a KEV CVE.

    The fix costs one statement per chunk. At 15,524 URLhaus rows and 30 per chunk
    that is ~518 extra round-trips per sync against a shared host, which is why the
    number matters rather than the principle.

    Structural rather than string-matched: an earlier version of these tests used
    substring heuristics and produced two false failures — the docstrings contain
    the word "for", and the sync chunk iterates `normalized` rather than `chunk`.
    AST is the only honest way to ask "is this call inside a loop".
    """

    @staticmethod
    def _function_node(name):
        import ast
        import inspect

        from app.services import feed_ingestion

        tree = ast.parse(inspect.getsource(feed_ingestion))
        for node in ast.walk(tree):
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)) and node.name == name:
                return node
        raise AssertionError(f"{name} not found")

    @staticmethod
    def _calls_inside_loops(node):
        """Names of functions called from within any loop in this function body."""
        import ast

        inside = set()
        for sub in ast.walk(node):
            if isinstance(sub, (ast.For, ast.AsyncFor, ast.While)):
                for inner in ast.walk(sub):
                    if isinstance(inner, ast.Call):
                        fn = inner.func
                        name = getattr(fn, "id", None) or getattr(fn, "attr", None)
                        if name:
                            inside.add(name)
        return inside

    @staticmethod
    def _all_called(node):
        import ast

        names = set()
        for sub in ast.walk(node):
            if isinstance(sub, ast.Call):
                fn = sub.func
                name = getattr(fn, "id", None) or getattr(fn, "attr", None)
                if name:
                    names.add(name)
        return names

    def test_the_enrichment_fetch_queries_once_over_the_whole_chunk(self):
        """One IN-list query, not one per row."""
        import ast

        for name in ("_enrichments_for_async",):
            node = self._function_node(name)
            # The only loop in these helpers is the Python-side grouping of results.
            loops = [n for n in ast.walk(node)
                     if isinstance(n, (ast.For, ast.AsyncFor, ast.While))]
            assert len(loops) == 1, f"{name}: expected one grouping loop, got {len(loops)}"
            in_loop = self._calls_inside_loops(node)
            assert not ({"execute", "query", "all"} & in_loop), (
                f"{name} issues a query inside its loop: {sorted(in_loop)}"
            )

    def test_both_chunk_functions_fetch_enrichment_outside_the_loop(self):
        """Inside the per-row loop it would be a 30x N+1 within a single chunk."""
        for fn_name, builder in (("_ingest_chunk", "_enrichments_for_async"),):
            node = self._function_node(fn_name)
            assert builder in self._all_called(node), (
                f"{fn_name} never builds enrichment_map — the re-read path would "
                f"score without enrichment evidence again"
            )
            assert builder not in self._calls_inside_loops(node), (
                f"{fn_name} builds enrichment_map inside a loop"
            )

    def test_the_prelude_reads_are_all_grouped_and_bounded(self):
        """Four pre-loop reads per chunk — one more than before Section 0.5."""
        for fn_name, expected in (
            ("_ingest_chunk",
             {"_distinct_feed_counts_async", "_already_linked_async",
              "_enrichments_for_async"}),
        ):
            node = self._function_node(fn_name)
            called = self._all_called(node)
            missing = expected - called
            assert not missing, f"{fn_name} missing pre-loop reads: {sorted(missing)}"
            in_loop = self._calls_inside_loops(node)
            leaked = expected & in_loop
            assert not leaked, f"{fn_name} calls these inside a loop: {sorted(leaked)}"

    def test_enrichment_map_lookup_is_a_dict_get_not_a_query(self):
        """The per-row access must be an in-memory lookup."""
        import inspect

        from app.services import feed_ingestion

        src = inspect.getsource(feed_ingestion)
        assert src.count("enrichment_data=enrichment_map.get(existing.id, [])") == 1, (
            "the re-read path must pass enrichment_data (one path since the sync "
            "mirror was deleted on 2026-07-31)"
        )

    def test_malformed_enrichment_json_degrades_rather_than_raising(self):
        """One bad payload must not abort a 30-row chunk."""
        from app.services.feed_ingestion import _decode_json_column

        assert _decode_json_column(None, {}) == {}
        assert _decode_json_column("{not json", {}) == {}
        assert _decode_json_column('{"a": 1}', {}) == {"a": 1}
        assert _decode_json_column({"a": 1}, {}) == {"a": 1}
        assert _decode_json_column(b'{"a": 1}', {}) == {"a": 1}
        assert _decode_json_column(42, {}) == {}
