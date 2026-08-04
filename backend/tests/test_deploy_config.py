"""Deployment configuration that has to agree with code, asserted in CI.

Phase 6 work. Each of these pairs a value in a config file with a constant or an
assumption in the application, where a mismatch fails silently in production:

  * the feed-sync cron interval against `_GOVERNING_SYNC_INTERVAL_SECONDS`, which drives
    rolling-window gap detection - if cron fires less often than the constant claims, the
    window check under-reports gaps and indicators are lost with no warning;
  * the GeoLite2 build step against the credentials it needs, since the step fails open;
  * the `--workers 1` start command, covered in depth by tests/test_process_model.py and
    re-asserted here only as part of the deploy surface.

Written without pyyaml, which is not a project dependency - the cron line is parsed with a
regex over the workflow text. That is adequate because the assertion is about one scalar,
and adding a dependency to test a config file would be a poor trade.
"""

import pathlib
import re

import pytest

ROOT = pathlib.Path(__file__).resolve().parents[2]
WORKFLOW = ROOT / ".github" / "workflows" / "feed-sync.yml"
RENDER_YAML = ROOT / "render.yaml"


def _cron_expressions(text):
    """Every `- cron: "..."` value in a workflow, comments ignored."""
    found = []
    for raw in text.splitlines():
        code = raw.split("#", 1)[0]
        match = re.search(r'-\s*cron:\s*["\']([^"\']+)["\']', code)
        if match:
            found.append(match.group(1))
    return found


def _cron_interval_hours(expression):
    """Hours between firings for the `M H/N * * *` and `M H * * *` forms.

    Only the shapes this project uses. A cron expression is not generally reducible to an
    interval - `0 9,17 * * *` fires twice a day at uneven spacing - so this raises rather
    than guessing, which is the right failure for a test whose whole point is that the
    interval is knowable.
    """
    fields = expression.split()
    assert len(fields) == 5, f"expected 5 cron fields, got {expression!r}"
    hour = fields[1]
    if hour.startswith("*/"):
        return int(hour[2:])
    if hour == "*":
        return 1
    if hour.isdigit():
        return 24
    raise AssertionError(
        f"cron hour field {hour!r} does not reduce to a single interval. If the schedule "
        "is now uneven, this test needs to compare worst-case spacing against the "
        "governing constant rather than a single number."
    )


class TestFeedSyncCronMatchesTheGoverningInterval:
    """The loop the owner asked to close before the times are chosen."""

    def test_the_workflow_exists(self):
        assert WORKFLOW.exists(), (
            f"{WORKFLOW.relative_to(ROOT)} is missing. POST /api/v1/feeds/sync-all is the "
            "only live background path - the asyncio scheduler is never started and the "
            "Celery beat schedule is commented out - so without this nothing ingests."
        )

    def test_exactly_one_schedule_is_declared(self):
        """Two schedules would make "the interval" ambiguous."""
        expressions = _cron_expressions(WORKFLOW.read_text(encoding="utf-8"))
        assert len(expressions) == 1, (
            f"expected one cron expression, found {expressions}. With more than one, the "
            "comparison against _GOVERNING_SYNC_INTERVAL_SECONDS below is undefined - "
            "compare the worst-case gap instead."
        )

    def test_the_cron_interval_matches_the_governing_constant(self):
        """A mismatch is silent: gap detection under-reports and indicators vanish.

        `_GOVERNING_SYNC_INTERVAL_SECONDS` tells `BaseFeed`'s window-continuity check how
        much time can pass between syncs. If cron actually fires less often, records age
        out of a rolling window in the interval the check believes is covered, and nothing
        raises - the feed reports success having silently missed rows.
        """
        from app.feeds.malwarebazaar import MalwareBazaarFeed

        governing_hours = MalwareBazaarFeed._GOVERNING_SYNC_INTERVAL_SECONDS / 3600
        expression = _cron_expressions(WORKFLOW.read_text(encoding="utf-8"))[0]
        cron_hours = _cron_interval_hours(expression)

        assert cron_hours == governing_hours, (
            f"cron fires every {cron_hours}h ({expression!r}) but "
            f"_GOVERNING_SYNC_INTERVAL_SECONDS claims {governing_hours}h. These must "
            "change together in one commit: the constant drives rolling-window gap "
            "detection, so if cron is slower the check under-reports gaps and indicators "
            "are lost without an error."
        )

    def test_the_workflow_does_not_cancel_a_running_sync(self):
        """Killing a sync mid-chunk leaves the watermark behind the data it wrote."""
        text = WORKFLOW.read_text(encoding="utf-8")
        assert "cancel-in-progress: false" in text, (
            "the sync workflow may cancel an in-progress run. Ingestion commits per "
            "~30-row chunk and advances a watermark, so an interrupted run must be "
            "allowed to finish rather than be replaced by a newer one."
        )

    def test_the_workflow_fails_loudly_on_a_non_2xx(self):
        """A green cron job with a broken sync is the worst outcome available."""
        text = WORKFLOW.read_text(encoding="utf-8")
        assert "--fail-with-body" in text, (
            "curl is not failing the step on a non-2xx response, so ingestion could stop "
            "while the workflow stays green"
        )
        assert "set -euo pipefail" in text


class TestRenderConfigDeclaresWhatTheBuildNeeds:
    def test_the_geolite_download_has_its_credentials_declared(self):
        """The build step fails OPEN, so a missing credential is silent capability loss.

        `python download_geolite2.py || echo "...continuing"` cannot fail the build, and
        the script needs both MaxMind variables. Declaring them in render.yaml does not
        set them - they are `sync: false` - but it puts the dependency where someone
        reading the build command will see it.
        """
        text = RENDER_YAML.read_text(encoding="utf-8")
        if "download_geolite2" not in text:
            pytest.skip("the GeoLite2 build step has been removed")
        for key in ("MAXMIND_ACCOUNT_ID", "MAXMIND_LICENSE_KEY"):
            assert key in text, (
                f"render.yaml runs download_geolite2.py but never mentions {key}. The "
                "step swallows its own failure, so without the credentials GeoIP is "
                "silently absent for the entire IP population - PROJECT_SUMMARY §8 "
                "item 14."
            )

    def test_secrets_are_never_given_literal_values(self):
        """`sync: false` or `generateValue` only - a literal here is a committed secret.

        This repository already has live credentials in its history (see the rotation
        notice in SECURITY_REVIEW.md), so the cost of getting this wrong is established
        rather than theoretical.
        """
        text = RENDER_YAML.read_text(encoding="utf-8")
        sensitive = (
            "DATABASE_URL", "DATABASE_ASYNC_URL", "SECRET_KEY", "CRON_SECRET",
            "EMAIL_PASSWORD", "MAXMIND_LICENSE_KEY", "REDIS_URL",
        )
        lines = text.splitlines()
        offenders = []
        for i, raw in enumerate(lines):
            code = raw.split("#", 1)[0]
            match = re.search(r"-\s*key:\s*([A-Z0-9_]+)", code)
            if not match or match.group(1) not in sensitive:
                continue
            # The declaration's own block: everything up to the next `- key:`.
            for follow in lines[i + 1:]:
                follow_code = follow.split("#", 1)[0]
                if re.search(r"-\s*key:", follow_code):
                    break
                value = re.search(r"^\s*value:\s*(\S.*)$", follow_code)
                if value:
                    offenders.append(f"{match.group(1)} = {value.group(1).strip()}")
        assert not offenders, (
            "sensitive keys carry literal values in render.yaml: " + repr(offenders)
            + ". Use `sync: false` (set in the dashboard) or `generateValue: true`."
        )

    def test_the_start_command_declares_one_worker(self):
        """Re-asserted here as part of the deploy surface; depth is in
        tests/test_process_model.py, which also covers start.sh, gunicorn and the runtime
        refusal."""
        for raw in RENDER_YAML.read_text(encoding="utf-8").splitlines():
            code = raw.split("#", 1)[0]
            if "uvicorn" in code:
                assert "--workers 1" in code, code.strip()
                return
        pytest.fail("no uvicorn start command found in render.yaml")
