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
