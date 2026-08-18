"""Phase 4 Section E — which IOCs the cron enriches, and Shodan's retired exception.

THE OLD SELECTION was ``WHERE Enrichment.id IS NULL`` — never-enriched only. So an IOC
enriched once was never enriched again, ``expires_at`` rolled over nothing, and every
"temporary until the cache expires" fallback became permanent.

THE NEW SELECTION adds expired rows, minus error payloads. The exclusion is not tidiness:
a failed enricher stores its ``{"error": ...}`` with a full TTL, so a permanently broken
source would be re-attempted every time that TTL lapsed — four times a day at the 6-hour
TTL, forever, each attempt reproducing the identical failure and consuming a slot in
``enrich_limit``. Measured: 5,947 Shodan rows, 12.4% of the enrichment table, none of
which ever carried data.
"""

import ast
import inspect
import re
from pathlib import Path

import pytest


class TestErrorMarkerKeysStayInSyncWithTheEnrichers:
    """The SQL predicate enumerates keys; the scoring engine prefix-matches them.

    Two definitions of "this payload is an error" is one more than is safe, so this
    fails if an enricher ever emits a marker the SQL side does not know about.
    """

    def _enricher_error_keys(self):
        root = Path(inspect.getfile(__import__("app.enrichers", fromlist=["x"]))).parent
        keys = set()
        files = sorted(root.glob("*_enricher.py"))
        for path in files:
            # TWO SHAPES, and missing the second made this check vacuous. A dict
            # literal writes `{"error": ...}` (colon), but geoip writes
            # `result["error_city"] = ...` (subscript) -- so a colon-only regex found
            # zero error_city keys and the coverage comparison passed against an empty
            # set. Caught by mutating _ERROR_MARKER_KEYS and seeing NO test fail.
            text = path.read_text(encoding="utf-8")
            for match in re.finditer(r'"(error[a-z_]*)"\s*(?::|\])', text):
                keys.add(match.group(1))
        return keys, files

    def test_the_extractor_finds_the_known_markers(self):
        """Non-emptiness before the comparison, or the test below is vacuous."""
        keys, files = self._enricher_error_keys()
        assert len(files) >= 8, f"only {len(files)} enricher modules scanned"
        assert "error" in keys, f"scanner found no plain 'error' key at all: {keys}"
        assert "error_city" in keys, (
            "the scanner missed geoip's error_city, which is written as a SUBSCRIPT "
            "assignment rather than a dict-literal key. With it missing the coverage "
            "test below compares against an incomplete set and passes vacuously."
        )

    def test_every_emitted_marker_is_covered_by_the_sql_predicate(self):
        from app.api.enrichment import _ERROR_MARKER_KEYS

        keys, _ = self._enricher_error_keys()
        missing = keys - set(_ERROR_MARKER_KEYS)
        assert not missing, (
            f"these error markers are emitted by enrichers but not listed in "
            f"_ERROR_MARKER_KEYS: {sorted(missing)}. A payload carrying one would be "
            "treated as SUCCESSFUL enrichment and re-attempted on every TTL lapse."
        )

    def test_it_agrees_with_the_scoring_engine_convention(self):
        """`_reached_a_verdict` prefix-matches `error` / `error_*`.

        Every key the SQL side enumerates must be one that convention also treats as a
        failure, or a payload could be excluded from refresh while still counting as
        assessed evidence.
        """
        from app.api.enrichment import _ERROR_MARKER_KEYS

        for key in _ERROR_MARKER_KEYS:
            assert key == "error" or key.startswith("error_"), (
                f"{key!r} is not matched by scoring_engine._reached_a_verdict's "
                "prefix convention, so the two definitions disagree"
            )


class TestTheSelectionPredicate:
    def _source(self):
        from app.api import enrichment

        return inspect.getsource(enrichment)

    def test_no_site_still_uses_the_never_enriched_only_predicate(self):
        """All five call sites must move together, or the cron half-refreshes."""
        source = self._source()
        assert "Enrichment.id.is_(None)" in source, (
            "the never-enriched arm vanished entirely; a brand-new IOC would never be "
            "picked up"
        )
        # It should appear ONLY inside the shared helper now, not at the call sites.
        assert source.count("Enrichment.id.is_(None)") == 1, (
            "Enrichment.id.is_(None) appears more than once, so at least one call site "
            "still uses the old never-enriched-only selection while others refresh"
        )

    def test_every_call_site_uses_the_shared_helper(self):
        source = self._source()
        assert source.count("_needs_enrichment()") >= 5, (
            "not all five selection sites use the shared predicate; they drifted apart "
            "once already, which is why it was centralised"
        )

    def test_expired_rows_are_included(self):
        src = inspect.getsource(__import__(
            "app.api.enrichment", fromlist=["x"]
        )._needs_enrichment)
        assert "expires_at" in src, (
            "the selection ignores expires_at, so cached enrichment never refreshes and "
            "the §2.7 fallbacks stay permanent"
        )

    def test_a_null_ttl_counts_as_expired(self):
        """Rows written before TTLs existed must not be frozen out forever."""
        src = inspect.getsource(__import__(
            "app.api.enrichment", fromlist=["x"]
        )._needs_enrichment)
        assert "expires_at.is_(None)" in src

    def test_error_payloads_are_excluded(self):
        src = inspect.getsource(__import__(
            "app.api.enrichment", fromlist=["x"]
        )._needs_enrichment)
        assert "_records_a_failure()" in src, (
            "error payloads are not excluded, so a permanently broken source is "
            "re-attempted on every TTL lapse forever"
        )
        # Negated, not asserted: we want rows that did NOT fail.
        assert "~_records_a_failure()" in src, (
            "the failure predicate is used un-negated, which would select ONLY the "
            "error rows — the exact inverse of the intent"
        )

    def test_the_failure_predicate_uses_json_paths_not_a_like(self):
        """Verified against MariaDB 11.8: a LIKE '%error%' also matches a payload whose
        free text merely contains the word, and matches `error_city` when only `error`
        was meant."""
        import textwrap

        src = inspect.getsource(__import__(
            "app.api.enrichment", fromlist=["x"]
        )._records_a_failure)
        tree = ast.parse(textwrap.dedent(src))
        called = {
            getattr(n.func, "attr", None) or getattr(n.func, "id", None)
            for n in ast.walk(tree) if isinstance(n, ast.Call)
        }
        assert called, "no calls extracted; the check would be vacuous"
        assert "json_extract" in called, "the predicate no longer uses a JSON path"
        # A CALL, not a mention: the docstring explains at length why LIKE is wrong, so
        # a substring check matches the explanation. Same shape as the ten or so other
        # comment-matching slips this project has logged.
        assert "like" not in called and "ilike" not in called, (
            "the failure predicate uses a LIKE, which also matches a payload whose free "
            "text merely contains the word 'error', and matches error_city when only "
            "error was meant"
        )


class TestTheTransientErrorGapIsRecorded:
    """A known consequence, written down rather than discovered later."""

    def test_the_gap_is_documented_next_to_the_code_that_causes_it(self):
        from app.api import enrichment

        source = inspect.getsource(enrichment)
        assert "TRANSIENT" in source.upper(), (
            "the selection excludes error payloads, which means a genuinely transient "
            "failure is never retried by the cron. That is an accepted trade, but it "
            "must be stated where the exclusion lives — 'errors are never retried' is "
            "the kind of property that becomes surprising six months later."
        )
        assert "get_ioc" in source, (
            "the mitigation (get_ioc enriches on view) is not named, so a reader cannot "
            "tell whether the gap is unbounded"
        )


class TestShodanIsGatedOnImportability:
    """The documented exception was retired because its premise stopped holding.

    It stayed registered to return an "explanatory payload" — useful when the reader
    could act on it by adding a key. But `shodan` is commented out of requirements.txt
    and is not transitive, so in the deployed environment the payload is
    {"error": "Shodan library not installed"} EVEN WHEN THE KEY IS SET. That points an
    operator at the credential when the package is the problem.

    NOTE THESE TESTS EXIST BECAUSE THE GATE IS INVISIBLE LOCALLY. `shodan` is importable
    in most dev environments, so `build_registry()` registers it here exactly as before
    and nothing in the suite would notice the production difference. The gate is
    therefore exercised by forcing the unavailable branch.
    """

    def test_the_gate_helper_exists_and_reports_the_real_state(self):
        from app.enrichers import _shodan_library_available

        assert isinstance(_shodan_library_available(), bool)

    def test_shodan_is_absent_when_the_library_is_not_importable(self, monkeypatch):
        import app.enrichers as enrichers

        monkeypatch.setattr(enrichers, "_shodan_library_available", lambda: False)
        registry = enrichers.build_registry()
        assert "shodan" not in registry, (
            "shodan is registered without its library, so every IP IOC gets an "
            "{'error': 'Shodan library not installed'} row with a 6-hour TTL"
        )

    def test_shodan_is_present_when_it_is_importable(self, monkeypatch):
        """The control. Without it the gate could be stuck off and look correct."""
        import app.enrichers as enrichers

        monkeypatch.setattr(enrichers, "_shodan_library_available", lambda: True)
        assert "shodan" in enrichers.build_registry()

    def test_no_ip_source_list_includes_shodan_when_it_is_gated_out(
        self, monkeypatch, request
    ):
        """The consequence that matters: it must stop being an APPLICABLE source."""
        import app.enrichers as enrichers
        from app.services.enrichment_engine import _get_applicable_sources

        monkeypatch.setattr(enrichers, "_shodan_library_available", lambda: False)
        # THE REGISTRY IS CACHED (`get_registry`/`reset_registry`), so patching the gate
        # after it has been built changes nothing. Reset before AND after: before so the
        # patch takes effect, after so a gated-out registry does not leak into every
        # later test in the session and silently weaken them.
        enrichers.reset_registry()
        request.addfinalizer(enrichers.reset_registry)
        assert "shodan" not in _get_applicable_sources("ip"), (
            "shodan is still an applicable source for IPs without its library, so every "
            "IP IOC would get an error row with a 6-hour TTL"
        )

    def test_shodan_is_applicable_for_ips_when_the_library_is_present(
        self, monkeypatch, request
    ):
        """The control for the test above."""
        import app.enrichers as enrichers
        from app.services.enrichment_engine import _get_applicable_sources

        monkeypatch.setattr(enrichers, "_shodan_library_available", lambda: True)
        enrichers.reset_registry()
        request.addfinalizer(enrichers.reset_registry)
        assert "shodan" in _get_applicable_sources("ip")

    def test_the_key_check_survives_as_a_second_barrier(self):
        """Importable-but-unconfigured is a real local state, and there the explanatory
        payload IS actionable — so the in-enricher check is not redundant."""
        from app.enrichers.shodan_enricher import ShodanEnricher

        source = inspect.getsource(ShodanEnricher.enrich)
        assert "SHODAN_API_KEY" in source
