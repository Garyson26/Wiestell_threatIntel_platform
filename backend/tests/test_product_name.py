"""The product is Wiestell. Nothing a user or a third party sees may name SENTINEL.

SENTINEL was the internal name. The August 2026 rename fixed the public `/health`
`service` field and the feed User-Agent, and the guard written alongside it checked
exactly those: the health endpoints. Everything else in the same class stayed invisible
to it and stayed wrong for three months: the AI system prompt (so the assistant called
itself SENTINEL AI), the daily brief summary on the reports page, the STIX description
that lands in other organisations' tooling, the export filenames, the AI report author
and the OpenAPI title.

So this module guards the class, twice over:

* `TestEverySurfaceNamesTheProduct` drives each served string through the code that
  produces it and asserts the product name is PRESENT, not merely that the old one is
  absent. An absence check alone passes on an empty string.
* `TestNoOldNameAnywhereInTheRepository` searches every file for the old name, with an
  explicit allowlist for the comments that record the rename itself. A surface nobody
  has thought of yet is covered without anyone remembering to add it.
"""

import json
import pathlib
import re
import shutil
import subprocess

import pytest

from app.api import deps
from app.database import get_db
from app.main import app

from tests.conftest import make_user

PRODUCT = "wiestell"
OLD_NAME = re.compile("sentinel", re.IGNORECASE)


def _names_the_product(text: str, where: str) -> None:
    assert text, f"{where}: empty, so the check would be vacuous"
    assert not OLD_NAME.search(text), f"{where} still names SENTINEL: {text!r}"
    assert PRODUCT in text.lower(), f"{where} does not name Wiestell: {text!r}"


class _EmptyResult:
    """Every query answers 'nothing': zero counts, no rows."""

    def scalar(self):
        return 0

    def scalars(self):
        return self

    def all(self):
        return []

    def first(self):
        return None

    def __iter__(self):
        return iter([])


class _EmptySession:
    def __init__(self):
        self.added = []

    async def execute(self, *args, **kwargs):
        return _EmptyResult()

    async def flush(self):
        pass

    async def commit(self):
        pass

    async def rollback(self):
        pass

    async def refresh(self, *args, **kwargs):
        pass

    def add(self, obj):
        self.added.append(obj)


@pytest.fixture
def analyst_with_empty_db(client):
    """Bypass auth as an analyst and serve an empty database."""
    session = _EmptySession()
    user = make_user(role="analyst")

    async def _db():
        yield session

    app.dependency_overrides[deps.get_current_user] = lambda: user
    app.dependency_overrides[get_db] = _db
    return client, session


class _CapturingGroq:
    """Stands in for AsyncGroq and records every message list sent to the model."""

    def __init__(self, reply: str):
        self.sent = []
        outer = self

        class _Completions:
            async def create(self, model, messages, temperature, **kw):
                outer.sent.append(messages)

                class _R:
                    choices = [
                        type("C", (), {"message": type("M", (), {"content": reply})()})()
                    ]

                return _R()

        self.chat = type("Chat", (), {"completions": _Completions()})()


class TestEverySurfaceNamesTheProduct:
    def test_stix_description(self):
        """The only surface that leaves the platform: it is imported into other
        organisations' tooling, where a stale name cannot be corrected by us."""
        from app.utils.stix_converter import export_stix_json

        bundle = json.loads(
            export_stix_json(
                [{"id": "1", "type": "domain", "value": "evil.example", "threat_score": 80}]
            )
        )
        indicators = [o for o in bundle["objects"] if o["type"] == "indicator"]
        assert indicators, "no indicator in the bundle; the check would be vacuous"
        _names_the_product(indicators[0]["description"], "STIX indicator description")
        assert not OLD_NAME.search(json.dumps(bundle)), "the STIX bundle names SENTINEL"

    def test_ai_system_prompt(self):
        from app.services.groq_service import SYSTEM_PROMPT

        _names_the_product(SYSTEM_PROMPT, "AI system prompt")

    async def test_nothing_sent_to_the_model_names_the_old_name(self):
        """The prompt is not the only input. Check every message on all three call
        paths, so a second source of the old name would surface here."""
        from app.services.groq_service import GroqService

        service = GroqService()
        service.api_key = "test"
        fake = _CapturingGroq('{"summary": "s", "risk_level": "low", "analysis": "a", '
                              '"recommendations": []}')
        service._client = fake

        await service.analyze_ioc("domain", "evil.example", [{"source": "dns", "data": {}}])
        await service.chat([{"role": "user", "content": "who are you?"}], system_context="ctx")
        await service.generate_ai_report([{"type": "domain", "value": "evil.example"}], {"n": 1})

        assert len(fake.sent) == 3, f"expected 3 model calls, captured {len(fake.sent)}"
        for messages in fake.sent:
            for m in messages:
                assert not OLD_NAME.search(m["content"]), (
                    f"a {m['role']} message sent to the model names SENTINEL"
                )

    async def test_daily_brief_summary(self):
        """Shown as the report summary on the reports page."""
        from app.services.report_generator import generate_daily_brief

        session = _EmptySession()
        report = await generate_daily_brief(session)
        _names_the_product(report.summary, "daily brief summary")

    @pytest.mark.parametrize("fmt, suffix", [("csv", ".csv"), ("stix", ".stix.json")])
    def test_export_filename(self, analyst_with_empty_db, fmt, suffix):
        client, _ = analyst_with_empty_db
        resp = client.post("/api/v1/iocs/export", json={"format": fmt})
        assert resp.status_code == 200, resp.text
        disposition = resp.headers.get("content-disposition", "")
        filename = disposition.partition("filename=")[2]
        assert filename.endswith(suffix), disposition
        _names_the_product(filename, f"{fmt} export filename")

    def test_ai_report_author(self, analyst_with_empty_db, monkeypatch):
        """`created_by` is stored on the report row and returned by the reports API."""
        from app.services.groq_service import groq_service

        async def _fake_report(ioc_data, stats):
            return {"title": "t", "content": "c"}

        monkeypatch.setattr(type(groq_service), "is_available", property(lambda self: True))
        monkeypatch.setattr(groq_service, "generate_ai_report", _fake_report)

        client, session = analyst_with_empty_db
        client.post("/api/v1/ai/report")
        reports = [o for o in session.added if type(o).__name__ == "Report"]
        assert reports, "the handler stored no report; the check would be vacuous"
        _names_the_product(reports[0].created_by, "AI report created_by")

    def test_openapi_title(self):
        _names_the_product(app.title, "FastAPI title")
        _names_the_product(app.openapi()["info"]["title"], "OpenAPI info.title")

    def test_health_endpoints_agree_on_the_service_name(self, client, monkeypatch):
        """Public and unauthenticated. All three answer the same question, so a client
        comparing them should get one answer."""
        import app.database as database

        class _Session:
            async def __aenter__(self):
                return self

            async def __aexit__(self, *exc):
                return False

            async def execute(self, *args, **kwargs):
                return None

        monkeypatch.setattr(database, "AsyncSessionLocal", _Session)

        names = {}
        for path in ("/", "/health", "/api/v1/health"):
            resp = client.get(path)
            assert resp.status_code == 200, (path, resp.text)
            names[path] = resp.json()["service"]
        for path, name in names.items():
            _names_the_product(name, f"{path} service field")
        assert set(names.values()) == {"wiestell-api"}, names

    def test_feed_user_agent(self):
        """Every upstream feed operator sees this, and abuse.ch ties it to an account."""
        from app.feeds.base import BaseFeed

        class _Probe(BaseFeed):
            async def fetch(self):
                return None

            async def parse(self, raw_data):
                return []

        _names_the_product(_Probe().client.headers["user-agent"], "feed User-Agent")


ROOT = pathlib.Path(__file__).resolve().parents[2]
THIS_FILE = pathlib.Path(__file__).resolve().relative_to(ROOT).as_posix()

# Directories that are never part of the repository's content. Only used by the
# fallback walk; `git ls-files` already excludes them.
_SKIP_DIRS = {
    ".git", "node_modules", ".next", "__pycache__", ".pytest_cache", ".mypy_cache",
    ".ruff_cache", ".venv", "venv", "env", "build", "dist", "out", "coverage",
}

# (path, text the line contains, why the old name must stay there). Matched by line
# content rather than number so unrelated edits do not break it. Every entry must
# still match something: a stale entry fails, so the list cannot quietly grow.
ALLOWED = [
    # The rename's own history.
    ("backend/app/feeds/base.py", 'Renamed from "SENTINEL-TIP/1.0" on',
     "records the User-Agent rename"),
    ("backend/app/feeds/base.py", "SENTINEL is the internal",
     "records the User-Agent rename"),
    ("backend/app/main.py", 'It read "sentinel-api" until 2026-08-17',
     "records the health-endpoint rename"),
    ("render.yaml", "A `sentinel-frontend` web service was declared here",
     "records why the frontend service was removed"),
    ("render.yaml", "service named `sentinel-backend`",
     "records why the frontend service was removed"),
    # Old wording still gets an answer.
    ("frontend/src/app/(protected)/ai-assistant/page.tsx", "'how does sentinel work'",
     "the assistant's phrase matcher, so old wording still gets an answer"),
    ("frontend/src/app/(protected)/ai-assistant/page.tsx", "'how does sentinel'",
     "the assistant's phrase matcher, so old wording still gets an answer"),
    # Code that has to name the old values to do its job.
    ("frontend/src/lib/storageKeys.ts", "these were `sentinel_token` and",
     "the storage migration; remove with it"),
    ("frontend/src/lib/storageKeys.ts", "`sentinel_user_activities`. Renaming a key",
     "the storage migration; remove with it"),
    ("frontend/src/lib/storageKeys.ts", "[TOKEN_KEY, 'sentinel_token']",
     "the storage migration; remove with it"),
    ("frontend/src/lib/storageKeys.ts", "[ACTIVITIES_KEY, 'sentinel_user_activities']",
     "the storage migration; remove with it"),
    ("frontend/src/lib/storageKeys.ts", "build writes `sentinel_token`",
     "the storage migration; remove with it"),
    ("backend/tests/conftest_mysql.py", "still holds the old sentinel credentials",
     "tells a developer with a pre-rename volume what is in it"),
    ("backend/tests/conftest_mysql.py", "MYSQL_TEST_URL=mysql+pymysql://root:sentinel@",
     "tells a developer with a pre-rename volume how to keep using it"),
    # Left deliberately: something outside the repository may match on them.
    ("backend/app/main.py", 'logger.info("sentinel_starting"',
     "log event; a log search or alert configured in Render's dashboard may match it"),
    ("backend/app/main.py", 'logger.info("sentinel_shutting_down")',
     "log event; a log search or alert configured in Render's dashboard may match it"),
]


def _repository_files():
    """Every file that is, or could be committed as, part of the repository.

    With git: tracked files plus untracked files that are not ignored. CI has no git
    (the job runs in python:3.11.9-slim, so actions/checkout downloads a tarball with no
    .git), and there the tree on disk is exactly the tracked files, so walk it.
    """
    if (ROOT / ".git").exists() and shutil.which("git"):
        out = subprocess.run(
            ["git", "ls-files", "-z", "--cached", "--others", "--exclude-standard"],
            cwd=ROOT, capture_output=True, check=True,
        ).stdout.decode("utf-8")
        return sorted(p for p in out.split("\0") if p and (ROOT / p).is_file())
    return _walk()


def _walk():
    found = []
    for path in ROOT.rglob("*"):
        rel = path.relative_to(ROOT)
        if any(part in _SKIP_DIRS for part in rel.parts) or not path.is_file():
            continue
        found.append(rel.as_posix())
    return sorted(found)


def _old_name_lines(files):
    """(path, line number, line) for every line naming the old name; binaries skipped."""
    hits = []
    for rel in files:
        if rel == THIS_FILE:  # this guard has to name what it searches for
            continue
        data = (ROOT / rel).read_bytes()
        if b"\0" in data[:8192]:
            continue
        for n, line in enumerate(data.decode("utf-8", errors="replace").splitlines(), 1):
            if OLD_NAME.search(line):
                hits.append((rel, n, line.strip()))
    return hits


class TestNoOldNameAnywhereInTheRepository:
    #: Files that must be among those scanned, one per kind of file the old name has
    #: lived in. Checked so a listing that silently shrinks fails rather than passing.
    MUST_SCAN = {
        "backend/app/main.py", "backend/alembic.ini", "backend/start.sh",
        "backend/tests/conftest_mysql.py", "frontend/src/lib/storageKeys.ts",
        "frontend/src/app/globals.css", "frontend/tailwind.config.ts",
        "frontend/src/app/(protected)/ai-assistant/page.tsx", "docker-compose.yml",
        "render.yaml", "README.md", "CLAUDE.md", "scripts/seed_feeds.py",
        ".github/workflows/tests.yml",
    }
    #: Files in the repository on 2026-11-12: 243.
    MIN_FILES = 240

    def test_the_listing_covers_the_repository(self):
        files = _repository_files()
        assert len(files) >= self.MIN_FILES, (
            f"only {len(files)} files listed; the scan would pass over a fraction of the "
            "repository"
        )
        missing = self.MUST_SCAN - set(files)
        assert not missing, f"files the scan must cover were not listed: {sorted(missing)}"

    @pytest.mark.skipif(shutil.which("git") is None or not (ROOT / ".git").exists(),
                        reason="compares the CI walk against git; needs a git checkout")
    def test_the_ci_walk_lists_every_tracked_file(self):
        """CI takes the walk branch, so check that branch here, where git can vouch for it."""
        tracked = subprocess.run(
            ["git", "ls-files", "-z"], cwd=ROOT, capture_output=True, check=True,
        ).stdout.decode("utf-8").split("\0")
        missing = {p for p in tracked if p and (ROOT / p).is_file()} - set(_walk())
        assert not missing, f"the walk CI uses would miss: {sorted(missing)[:10]}"

    def test_the_old_name_appears_only_where_allowed(self):
        hits = _old_name_lines(_repository_files())
        assert hits, (
            "no occurrence found at all, not even the allowlisted ones; the scan is not "
            "reading files"
        )
        unexplained = [
            f"{path}:{n}: {line[:120]}"
            for path, n, line in hits
            if not any(path == p and needle in line for p, needle, _ in ALLOWED)
        ]
        assert not unexplained, (
            "SENTINEL is the old name. Use Wiestell, or if this occurrence must stay, add it "
            "to ALLOWED with the reason:\n  " + "\n  ".join(unexplained)
        )

    def test_every_allowance_is_still_needed(self):
        hits = _old_name_lines(_repository_files())
        stale = [
            (p, needle) for p, needle, _ in ALLOWED
            if not any(path == p and needle in line for path, _, line in hits)
        ]
        assert not stale, f"ALLOWED entries that no longer match anything: {stale}"
