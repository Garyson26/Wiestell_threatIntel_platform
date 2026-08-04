"""The worker count is part of the security model, so it is tested like one.

Four conclusions elsewhere in this codebase assume ONE process per instance. Render's
Hobby tier gives one *instance*, but the start command decides how many workers run
inside it, and uvicorn's default of 1 is a default rather than a declaration - nothing
stated it and nothing checked it until 2026-07-31.

What breaks at N workers:

  1. **Rate limiting.** `rate_limiter` falls back to an in-process dict without
     `REDIS_URL`. N workers means N independent budgets, so the effective limit is
     N x AUTH_RATE_LIMIT_MAX. This is what makes SECURITY_REVIEW.md residual risk #5's
     narrowing valid - the claim that the in-memory limiter is "effectively correct on
     this deployment" is true at one worker and false at two.
  2. **Connection pool.** `pool_size=2 + max_overflow=3` is per process, so N workers
     allow 5N connections against a SHARED Hostinger account allowance commonly capped
     at 25-75 for the whole account. Four workers puts it straight back to the 20-30 the
     Phase 5 resize existed to avoid.
  3. **Enrichment concurrency.** `_enrichment_semaphore` is module-level, deliberately,
     so the bound is process-wide. At N workers the real ceiling is 5N third-party calls
     in flight, which reintroduces the 429s the semaphore was added to prevent.
  4. **Any in-process cache** would become N caches serving inconsistent reads.

So this file exists to make raising the worker count a deliberate act that fails the
suite, rather than a one-word edit to a start command that quietly invalidates a security
finding, a resource limit and a rate-limit conclusion at once.
"""

import pathlib
import re

import pytest

ROOT = pathlib.Path(__file__).resolve().parents[2]
START_SH = ROOT / "backend" / "start.sh"
RENDER_YAML = ROOT / "render.yaml"


def _uvicorn_lines(text):
    """Executable lines invoking uvicorn, with comments stripped.

    Comments are removed first because the ones in both files *explain* the worker
    constraint and name the failure modes - matching raw text would hit the prose rather
    than the command. That trap has bitten six times in this project; see the standing
    rule in CLAUDE.md.
    """
    lines = []
    for raw in text.splitlines():
        code = raw.split("#", 1)[0]
        if "uvicorn" in code:
            lines.append(code.strip())
    return lines


class TestTheWorkerCountIsPinnedToOne:
    @pytest.mark.parametrize("path", [START_SH, RENDER_YAML], ids=["start.sh", "render.yaml"])
    def test_every_uvicorn_invocation_declares_one_worker(self, path):
        commands = _uvicorn_lines(path.read_text(encoding="utf-8"))
        assert commands, f"no uvicorn invocation found in {path.name}"
        for command in commands:
            assert "--workers 1" in command, (
                f"{path.name} starts uvicorn without an explicit --workers 1: "
                f"{command!r}\n"
                "One worker is assumed by the rate limiter, the connection pool, the "
                "enrichment semaphore and any in-process cache. Relying on uvicorn's "
                "default leaves that assumption undeclared and untested."
            )

    @pytest.mark.parametrize("path", [START_SH, RENDER_YAML], ids=["start.sh", "render.yaml"])
    def test_no_invocation_asks_for_more_than_one(self, path):
        """Catches `--workers 4` even if a `--workers 1` also appears somewhere."""
        for command in _uvicorn_lines(path.read_text(encoding="utf-8")):
            for count in re.findall(r"--workers[ =](\d+)", command):
                assert int(count) == 1, (
                    f"{path.name} requests {count} workers. Raising this requires "
                    "revisiting all four assumptions listed in this module's docstring: "
                    "Redis for the limiter and any cache, a smaller pool_size, and a "
                    "shared bound for enrichment concurrency."
                )

    def test_gunicorn_is_not_used(self):
        """gunicorn defaults to 2 x cores + 1, so reaching for it silently multiplies.

        Checked across every file that could plausibly start the app, rather than only
        the two known ones, because the danger is a *new* start path rather than an edit
        to an existing one.
        """
        candidates = [
            ROOT / "render.yaml",
            ROOT / "vercel.json",
            ROOT / "docker-compose.yml",
            ROOT / "backend" / "Dockerfile",
            ROOT / "backend" / "start.sh",
        ]
        offenders = []
        for path in candidates:
            if not path.exists():
                continue
            for raw in path.read_text(encoding="utf-8").splitlines():
                code = raw.split("#", 1)[0]
                if "gunicorn" in code:
                    offenders.append(f"{path.name}: {code.strip()}")
        assert not offenders, (
            "gunicorn appears in a start path: " + repr(offenders)
            + ". Its default worker count is 2 x cores + 1, so it multiplies the "
            "per-process assumptions listed in this module's docstring without anyone "
            "typing a number."
        )


class TestTheRuntimeRefusal:
    """The file tests above guard the repo; this guards the deployment.

    Render's dashboard allows a start-command override that lives in no file, and so does
    `docker run` with different arguments, or a developer carrying `--workers 4` forward
    from a debugging session. None of those touch anything a grep can read, so the check
    has to exist at startup as well.

    Worker children **do** inherit `sys.argv` - verified empirically 2026-07-31 against
    uvicorn on Windows, which uses spawn and therefore re-executes each worker: all three
    processes reported the parent's full argv including `--workers 2`. So the refusal fires
    in every worker rather than only the supervisor.
    """

    @staticmethod
    def _check(argv, env=None, monkeypatch=None):
        import sys

        from app.main import _assert_single_worker

        monkeypatch.setattr(sys, "argv", argv)
        monkeypatch.delenv("ALLOW_MULTIPLE_WORKERS", raising=False)
        for key, value in (env or {}).items():
            monkeypatch.setenv(key, value)
        return _assert_single_worker()

    def test_a_single_worker_passes(self, monkeypatch):
        assert self._check(
            ["uvicorn", "app.main:app", "--workers", "1"], monkeypatch=monkeypatch
        ) is None

    def test_an_absent_flag_passes(self, monkeypatch):
        """uvicorn's default is 1, so no flag is the same as one worker."""
        assert self._check(
            ["uvicorn", "app.main:app", "--port", "8000"], monkeypatch=monkeypatch
        ) is None

    @pytest.mark.parametrize("argv", [
        ["uvicorn", "app.main:app", "--workers", "2"],
        ["uvicorn", "app.main:app", "--workers", "4", "--port", "8000"],
        ["uvicorn", "app.main:app", "--workers=8"],
    ], ids=["two", "four", "equals-form"])
    def test_multiple_workers_are_refused(self, argv, monkeypatch):
        with pytest.raises(RuntimeError, match="uvicorn workers requested"):
            self._check(argv, monkeypatch=monkeypatch)

    def test_the_override_env_var_opens_the_door(self, monkeypatch):
        """For someone who has actually revisited all four assumptions."""
        assert self._check(
            ["uvicorn", "app.main:app", "--workers", "4"],
            env={"ALLOW_MULTIPLE_WORKERS": "true"},
            monkeypatch=monkeypatch,
        ) is None

    @pytest.mark.parametrize("value", ["1", "yes", "TRUE", " true "])
    def test_the_override_accepts_the_usual_truthy_spellings(self, value, monkeypatch):
        assert self._check(
            ["uvicorn", "app.main:app", "--workers", "3"],
            env={"ALLOW_MULTIPLE_WORKERS": value},
            monkeypatch=monkeypatch,
        ) is None

    @pytest.mark.parametrize("value", ["0", "false", "no", ""])
    def test_a_falsy_override_still_refuses(self, value, monkeypatch):
        with pytest.raises(RuntimeError):
            self._check(
                ["uvicorn", "app.main:app", "--workers", "3"],
                env={"ALLOW_MULTIPLE_WORKERS": value},
                monkeypatch=monkeypatch,
            )

    def test_a_malformed_worker_value_is_not_our_problem(self, monkeypatch):
        """uvicorn validates its own arguments; this must not raise on nonsense."""
        assert self._check(
            ["uvicorn", "app.main:app", "--workers", "many"], monkeypatch=monkeypatch
        ) is None

    def test_the_refusal_names_all_four_consequences(self, monkeypatch):
        """The message is the only thing an operator will read at 2am."""
        with pytest.raises(RuntimeError) as excinfo:
            self._check(["uvicorn", "app.main:app", "--workers", "4"],
                        monkeypatch=monkeypatch)
        message = str(excinfo.value)
        for expected in ("rate limiter", "pool", "semaphore", "cache",
                        "ALLOW_MULTIPLE_WORKERS"):
            assert expected in message, f"the refusal does not mention {expected!r}"


class TestTheAssumptionsThatDependOnIt:
    """Pins the per-process values, so the coupling is visible from this file too.

    If someone finds this module while raising the worker count, these assertions name
    exactly what has to change alongside it.
    """

    def test_the_pool_is_per_process_and_small(self):
        from app.database import async_engine

        per_process = async_engine.pool.size() + async_engine.pool._max_overflow
        assert per_process == 5, (
            f"{per_process} connections per process. At N workers the account-wide total "
            "is N x this, against a shared allowance commonly capped at 25-75."
        )

    def test_the_enrichment_bound_is_per_process(self):
        from app.services import enrichment_engine

        assert enrichment_engine.ENRICHMENT_CONCURRENCY == 5, (
            "the enrichment ceiling changed; it is per process, so the real in-flight "
            "total is workers x this"
        )

    def test_the_rate_limiter_falls_back_to_process_local_state(self):
        """The property that makes the worker count a security concern.

        Not a defect on its own - it is correct at one worker - but it is the reason the
        worker count belongs in the security model rather than in a performance note.
        """
        from app.utils.rate_limiter import rate_limiter

        assert hasattr(rate_limiter, "check_rate_limit")
        # No Redis configured in the test environment, so this is the fallback path.
        key = "test-process-model"
        assert rate_limiter.check_rate_limit(key, 1, 60) is True
        assert rate_limiter.check_rate_limit(key, 1, 60) is False, (
            "the limiter did not enforce its budget within one process, which is the "
            "only place it can enforce anything without Redis"
        )

class TestDegradedStatesAreSurfacedButNotPublished:
    """Both states are reported to an admin, and NEITHER leaks to an anonymous caller.

    They were briefly on the public `/health` payload. That was a poor trade:
    `/health` has to stay unauthenticated for Render's health checker, so anything on it is
    world-readable - and `multiple_workers_allowed` tells an unauthenticated reader that the
    login rate limit is N times weaker than it appears, which is precisely the fact worth
    having before starting a credential-stuffing run. Publishing one's own mitigation gap
    for post-deploy convenience is not worth it. Moved to `/cron-status`, which is already
    admin-gated and already exists to report operational state.
    """

    @staticmethod
    def _degradations(monkeypatch, allow=None, geoip_present=False, tmp_path=None):
        from app.config import settings
        from app.enrichers import reset_registry
        from app.main import _deployment_degradations

        monkeypatch.delenv("ALLOW_MULTIPLE_WORKERS", raising=False)
        if allow is not None:
            monkeypatch.setenv("ALLOW_MULTIPLE_WORKERS", allow)
        if geoip_present:
            db = tmp_path / "GeoLite2-City.mmdb"
            db.write_bytes(b"stub")
            monkeypatch.setattr(settings, "GEOIP_DB_PATH", str(db))
        else:
            monkeypatch.setattr(settings, "GEOIP_DB_PATH", "/nonexistent/x.mmdb")
        reset_registry()
        return {d["id"] for d in _deployment_degradations()}

    def test_a_correct_deployment_reports_nothing(self, monkeypatch, tmp_path):
        assert self._degradations(
            monkeypatch, geoip_present=True, tmp_path=tmp_path) == set()

    def test_a_missing_geoip_database_is_reported(self, monkeypatch, tmp_path):
        assert "geoip_database_missing" in self._degradations(
            monkeypatch, geoip_present=False, tmp_path=tmp_path)

    def test_the_worker_override_is_reported(self, monkeypatch, tmp_path):
        assert "multiple_workers_allowed" in self._degradations(
            monkeypatch, allow="true", geoip_present=True, tmp_path=tmp_path)

    def test_both_can_be_reported_at_once(self, monkeypatch, tmp_path):
        assert self._degradations(
            monkeypatch, allow="1", geoip_present=False, tmp_path=tmp_path) == {
            "geoip_database_missing", "multiple_workers_allowed"}

    def test_each_entry_says_what_it_costs_and_how_to_fix_it(self, monkeypatch, tmp_path):
        """The payload is read post-deploy by a person, so an id alone is not actionable."""
        from app.main import _deployment_degradations

        self._degradations(monkeypatch, allow="true", geoip_present=False,
                          tmp_path=tmp_path)
        entries = _deployment_degradations()
        assert entries, "fixture produced no degradations"
        for entry in entries:
            assert entry.get("impact"), f"{entry['id']} does not say what it costs"
            assert entry.get("fix"), f"{entry['id']} does not say how to fix it"

    def test_the_public_health_payload_does_NOT_carry_them(self, monkeypatch, tmp_path):
        """The disclosure guard. /health is unauthenticated by necessity.

        Asserts on the worst case - both degradations active - so the test cannot pass
        merely because there was nothing to leak.
        """
        import asyncio

        from app.config import settings
        from app.enrichers import reset_registry
        from app.main import health_check

        monkeypatch.setenv("ALLOW_MULTIPLE_WORKERS", "true")
        monkeypatch.setattr(settings, "GEOIP_DB_PATH", "/nonexistent/x.mmdb")
        reset_registry()

        payload = asyncio.run(health_check())
        serialised = repr(payload)

        assert "degradations" not in payload, (
            "the public health payload carries the degradations array. "
            "multiple_workers_allowed tells an unauthenticated reader the login rate "
            "limit is weaker than it appears; move it to /cron-status."
        )
        for leaked in ("multiple_workers", "ALLOW_MULTIPLE_WORKERS", "geoip_database",
                       "rate limits are per worker"):
            assert leaked not in serialised, (
                f"{leaked!r} appears in the public /health payload: {serialised}"
            )

    def test_health_still_reports_enough_to_be_a_probe(self):
        """Minimal is the goal, not empty. Render reads only the status CODE, so the body
        matters for future uptime monitoring rather than for current behaviour."""
        import asyncio

        from app.main import health_check

        payload = asyncio.run(health_check())
        assert payload.get("status") in {"healthy", "degraded"}
        assert "service" in payload

    def test_cron_status_is_admin_gated(self):
        """The move is only a fix if the destination is actually guarded."""
        from app.api.deps import require_admin
        from app.main import app

        for route in app.routes:
            if getattr(route, "path", None) == "/api/v1/cron-status":
                names = [
                    getattr(d.dependency, "__name__", "")
                    for d in getattr(route, "dependencies", [])
                ]
                assert any("role_checker" in n or "admin" in n for n in names), (
                    f"/cron-status dependencies are {names}; the degradations array is "
                    "only protected if this route requires admin"
                )
                return
        raise AssertionError("/api/v1/cron-status is not registered")
