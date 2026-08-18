"""`create_ioc` enriches in-request, and no handler serves a raw enrichment payload.

Two separate properties, both established on 2026-08-17 when `app/tasks/` was deleted.

**The Celery dispatch was a silent no-op.** `create_ioc` was the only handler in
`api/ioc.py` that did not await `enrich_ioc`; it called `enrich_ioc_task.delay(...)`
instead. `REDIS_URL` is unset in the deployed environment, so Celery fell back to its
default AMQP broker, the connection was refused, and a bare `except Exception: pass`
swallowed the error without a log line. Analyst-submitted IOCs were accepted with a 200
and never enriched. Measured, not inferred: `.delay()` raises
`OperationalError [WinError 10061]`.

**The stale-mean guards were per-handler and missed one.** The Spec 6c checks call
`inspect.getsource` on a NAMED handler, so `get_enrichment` — which nothing named — served
`e.data` raw, i.e. the pre-2026-07-31 reputation mean rather than the strongest provider
score. The guard here walks the whole `app/api` package instead of a list of names, so a
new handler is covered by default rather than on remembering to add it.

Per the CLAUDE.md rule about guards whose failure mode is silence: the AST extractor below
asserts what it FOUND before asserting what it did not, because an extractor that silently
matches nothing makes every downstream assertion pass vacuously. That has bitten this
project four times.
"""

import ast
import inspect
from pathlib import Path

import pytest


def _api_modules():
    """Every module in `app/api`, as (path, parsed tree)."""
    api_dir = Path(inspect.getfile(__import__("app.api", fromlist=["api"]))).parent
    for path in sorted(api_dir.glob("*.py")):
        yield path, ast.parse(path.read_text(encoding="utf-8"))


def _enrichment_payload_sites():
    """Every dict literal in `app/api` carrying a "data" key.

    Returns (module, lineno, value_node). This is the extraction step, so the tests that
    use it assert it is non-empty first.
    """
    sites = []
    for path, tree in _api_modules():
        for node in ast.walk(tree):
            if not isinstance(node, ast.Dict):
                continue
            for key, value in zip(node.keys, node.values):
                if isinstance(key, ast.Constant) and key.value == "data":
                    sites.append((path.name, getattr(value, "lineno", node.lineno), value))
    return sites


def _unnormalised_data_accesses():
    """Every `X.data` in `app/api` that is NOT an argument to the normaliser.

    This is the CLASS check. The dict-literal check below is the SHAPE check, and shape
    was not enough: the `get_enrichment` bug happened to be written as a dict literal, but
    the same defect reintroduced as ``dict(data=e.data)``, ``Model(data=e.data)``,
    ``payload["data"] = e.data`` or a comprehension over ``e.data`` is invisible to it.
    All four were measured slipping through on 2026-08-17.

    So this asserts on the VALUE rather than the container: an enrichment payload reaches
    a response only through an attribute access, whatever syntax wraps it.

    **There is deliberately no allowlist.** At the time of writing there are zero
    unnormalised `.data` accesses in `app/api`, so the rule needs no exceptions — and an
    allowlist is a maintenance surface that gets appended to under deadline, which is
    how the original per-handler guards ended up missing a handler. If a legitimate
    non-enrichment `.data` ever appears here (say `response.data` from some client), the
    correct fix is to narrow this predicate to the enrichment types, not to add a name to
    a skip list. It fails loudly, which is the point.
    """
    found, normalised = [], 0
    for path, tree in _api_modules():
        source = path.read_text(encoding="utf-8")
        for node in ast.walk(tree):
            if isinstance(node, ast.Call):
                name = getattr(node.func, "id", None) or getattr(node.func, "attr", None)
                if name == "normalize_enrichment_for_display":
                    for arg in node.args:
                        for sub in ast.walk(arg):
                            if isinstance(sub, ast.Attribute) and sub.attr == "data":
                                sub._normalised = True
                                normalised += 1
        for node in ast.walk(tree):
            if isinstance(node, ast.Attribute) and node.attr == "data":
                if getattr(node, "_normalised", False):
                    continue
                # NARROWED 2026-08-17, not skip-listed. `Enrichment.data` on the MODEL
                # CLASS is a Column descriptor used to build a SQL expression — it
                # cannot be serialised into a response, because it is a query construct
                # rather than a row value. `e.data` on an instance IS a row value and
                # stays flagged.
                #
                # This is the narrowing the docstring above anticipated: when a
                # legitimate non-serving `.data` appeared (Section E's error-payload
                # predicate), the fix was to make the predicate precise, not to add a
                # name to a skip list. A skip list would have exempted the file; this
                # exempts only the construct that provably cannot reach a client.
                if isinstance(node.value, ast.Name) and node.value.id == "Enrichment":
                    continue
                snippet = (ast.get_source_segment(source, node) or "?")
                found.append(f"{path.name}:{node.lineno}  {snippet}")
    return found, normalised


class TestNoHandlerServesARawEnrichmentPayload:
    """The property `get_enrichment` violated for two and a half weeks."""

    def test_the_value_flow_extractor_sees_the_normalised_accesses(self):
        """Non-emptiness for the CLASS check, same reasoning as the shape check."""
        _, normalised = _unnormalised_data_accesses()
        assert normalised >= 5, (
            f"the value-flow walker found only {normalised} normalised `.data` accesses; "
            "it previously found 5+. It has stopped matching, which would make "
            "test_no_raw_enrichment_payload_reaches_a_response vacuous."
        )

    def test_no_raw_enrichment_payload_reaches_a_response(self):
        """Catches the defect regardless of the syntax used to reintroduce it.

        Verified on 2026-08-17 by reintroducing it four ways — `dict(data=e.data)`,
        `_wrap(data=e.data)`, `payload["data"] = e.data`, and a comprehension over
        `e.data`. The dict-literal check missed all four; this one catches all four.
        """
        found, _ = _unnormalised_data_accesses()
        assert not found, (
            "these read an enrichment payload without normalize_enrichment_for_display, "
            f"so the response would carry the pre-2026-07-31 reputation MEAN: {found}. "
            "The container does not matter — dict literal, kwarg, subscript assignment "
            "or comprehension all reach the client the same way."
        )

    def test_the_extractor_actually_finds_the_known_sites(self):
        """Non-emptiness first. If this regex-equivalent stops matching, everything
        below passes for the wrong reason.

        Five sites were known on 2026-08-17: one in `ai.py` and four in `ioc.py`
        (`lookup_ioc`, `get_ioc`, `get_enrichment`, `export_iocs`). The floor is set
        below that count deliberately — this asserts the extractor WORKS, not that the
        site count is frozen.
        """
        sites = _enrichment_payload_sites()
        assert len(sites) >= 5, (
            f"the AST extractor found only {len(sites)} enrichment payload sites; it "
            "previously found 5. It has probably stopped matching, which would make "
            "test_every_site_goes_through_the_normaliser vacuous."
        )
        modules = {name for name, _, _ in sites}
        assert {"ai.py", "ioc.py"} <= modules, f"expected ai.py and ioc.py, got {modules}"

    def test_every_site_goes_through_the_normaliser(self):
        """A bare `.data` attribute serves the stored payload, mean included."""
        violations = []
        for module, lineno, value in _enrichment_payload_sites():
            if isinstance(value, ast.Call):
                func = value.func
                name = getattr(func, "id", None) or getattr(func, "attr", None)
                if name == "normalize_enrichment_for_display":
                    continue
            if isinstance(value, ast.Attribute) and value.attr == "data":
                violations.append(f"{module}:{lineno}")

        assert not violations, (
            f"these serve a raw enrichment payload: {violations}. Wrap the value in "
            "normalize_enrichment_for_display(e.source, e.data) — otherwise the response "
            "carries the pre-2026-07-31 reputation MEAN instead of the strongest provider "
            "score. This is exactly how get_enrichment was missed: the older guards named "
            "handlers one at a time."
        )


class TestCreateIocEnrichesInRequest:
    """`create_ioc` must match its five siblings, not dispatch into the void."""

    def _source(self):
        from app.api import ioc as ioc_api

        return inspect.getsource(ioc_api.create_ioc)

    def test_it_awaits_enrich_ioc(self):
        assert "await enrich_ioc(db, ioc)" in self._source(), (
            "create_ioc no longer enriches in-request. Every other handler in the module "
            "awaits enrich_ioc; reverting this one to a queue dispatch reintroduces the "
            "silent no-op, because no broker is provisioned."
        )

    def test_no_celery_dispatch_anywhere_in_the_api(self):
        """`.delay(` / `.apply_async(` are the two ways back to the old behaviour."""
        offenders = []
        for path, tree in _api_modules():
            for node in ast.walk(tree):
                if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute):
                    if node.func.attr in {"delay", "apply_async"}:
                        offenders.append(f"{path.name}:{node.lineno}")
        assert not offenders, (
            f"Celery-style dispatch is back at {offenders}, and app/tasks/ was deleted on "
            "2026-08-17. There is no broker: REDIS_URL is unset and the call will raise "
            "into whatever guard surrounds it."
        )

    def test_enrichment_failure_is_logged_rather_than_swallowed(self):
        """The bare `except: pass` is what made the dead dispatch invisible.

        `enrich_ioc` should not raise at all — enrichers return {"error": ...} — so if it
        does, that is a real defect and it must reach the log.
        """
        source = self._source()
        assert "logger.warning" in source, (
            "create_ioc catches enrichment failures without logging them. That is the "
            "exact shape that hid the dead Celery dispatch: an exception vanishing into "
            "`except Exception: pass` with no log line."
        )
        assert "create_ioc_enrichment_failed" in source
        assert "redact_secrets" in source, (
            "the logged exception string is not redacted; a driver error embeds the "
            "connection URI (CLAUDE.md, sanitize rule)."
        )

    def test_the_guard_does_not_swallow_silently(self):
        """Paired with the above: assert the except block is not a bare pass."""
        import textwrap

        tree = ast.parse(textwrap.dedent(self._source()))
        handlers = [n for n in ast.walk(tree) if isinstance(n, ast.ExceptHandler)]
        assert handlers, "expected create_ioc to guard the enrichment call"
        for handler in handlers:
            assert not all(isinstance(s, ast.Pass) for s in handler.body), (
                "create_ioc has an except block whose entire body is `pass`"
            )

    def test_it_returns_the_enrichment_it_just_produced(self):
        """Otherwise the analyst gets a bare IOC and must re-fetch to see the result."""
        from app.api import ioc as ioc_api

        source = self._source()
        assert "IOCDetailResponse" in source, (
            "create_ioc no longer returns the detail shape, so the enrichment it just "
            "ran is invisible to the caller."
        )
        assert "normalize_enrichment_for_display" in source

        route = next(
            r for r in ioc_api.router.routes
            if getattr(r, "name", None) == "create_ioc"
        )
        from app.schemas.ioc import IOCDetailResponse

        assert route.response_model is IOCDetailResponse, (
            f"declared response_model is {route.response_model}, so FastAPI will strip "
            "the enrichments field out of the response body even though the handler "
            "builds it."
        )


class TestTheTasksPackageIsGone:
    """It was imported at runtime, so its absence is a property worth asserting."""

    def test_app_tasks_cannot_be_imported(self):
        with pytest.raises(ImportError):
            __import__("app.tasks")

    def test_celery_is_not_a_declared_dependency(self):
        req = Path(__file__).resolve().parents[1] / "requirements.txt"
        lines = [
            ln.strip() for ln in req.read_text(encoding="utf-8").splitlines()
            if ln.strip() and not ln.strip().startswith("#")
        ]
        assert lines, "requirements.txt parsed as empty — the check would be vacuous"
        assert not [ln for ln in lines if ln.lower().startswith("celery")], (
            "celery is pinned again but app/tasks/ is gone"
        )
