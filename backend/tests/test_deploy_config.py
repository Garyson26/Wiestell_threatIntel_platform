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


def _cron_firing_hours(hour_field):
    """The set of hours a cron hour-field fires at. Handles `*`, `*/N` and `a,b,c`."""
    if hour_field == "*":
        return list(range(24))
    if hour_field.startswith("*/"):
        step = int(hour_field[2:])
        return list(range(0, 24, step))
    hours = []
    for part in hour_field.split(","):
        part = part.strip()
        if not part.isdigit():
            raise AssertionError(
                f"cron hour field {hour_field!r} contains {part!r}, which this parser "
                "does not understand (ranges like 9-17 are not handled). Extend it or "
                "simplify the schedule."
            )
        hours.append(int(part))
    return sorted(set(hours))


def _cron_interval_hours(expression):
    """Hours between firings, for any evenly-spaced schedule.

    **Widened 2026-07-31.** The first version only understood `*/N` and raised on the
    enumerated form, which made it stricter than the constraint it was enforcing:
    `17 0,6,12,18 * * *` is evenly spaced and perfectly correct, and it was rejected. The
    fix is the worst-case-gap comparison that was the right shape all along - derive the
    firing hours, diff them **including the midnight wraparound**, and require the gaps to
    be equal.

    Still raises on a genuinely uneven schedule (`0 9,17,21,23 * * *`), because such a
    schedule has no single interval to compare against the governing constant. That is the
    correct failure for a test whose whole premise is that the interval is knowable - but
    the message now says what to do about it rather than just refusing.
    """
    fields = expression.split()
    assert len(fields) == 5, f"expected 5 cron fields, got {expression!r}"

    hours = _cron_firing_hours(fields[1])
    assert hours, f"cron expression {expression!r} never fires"
    if len(hours) == 1:
        return 24

    # The wraparound gap matters: 0,6,12,18 has gaps 6,6,6 within the day and a further 6
    # from 18 back to 00 the next day. Omitting it would accept 0,6,12 as "every 6 hours"
    # when the real worst case is the 12-hour overnight gap.
    gaps = [b - a for a, b in zip(hours, hours[1:])]
    gaps.append(24 - hours[-1] + hours[0])

    if len(set(gaps)) != 1:
        raise AssertionError(
            f"cron expression {expression!r} fires at hours {hours} with uneven gaps "
            f"{gaps}, so it has no single interval to compare against "
            "_GOVERNING_SYNC_INTERVAL_SECONDS. Either even out the schedule, or change "
            "the constant to describe the WORST-CASE gap "
            f"({max(gaps)}h here) and compare against that instead - the worst case is "
            "what rolling-window gap detection actually needs to survive."
        )
    return gaps[0]


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


class TestTheWorkflowDistinguishesEndpointFromFeedFailure:
    """A badge that is red most days is a badge nobody reads.

    `--fail-with-body` correctly fails the step on a non-2xx from our own endpoint. But a
    200 carrying `status: failed` for ONE feed is the normal path - third-party sources
    rate-limit, move URLs and go down, which is what `feed_sources.consecutive_failures`
    and its backoff exist to absorb. The classifier step must therefore fail on a non-2xx,
    a timeout or an unparseable body, and NOT on a partial feed failure - while still
    failing when EVERY feed failed, because that is systemic rather than flaky.

    The classifier is extracted from the workflow and executed here, so this tests the
    shipped code rather than a copy of it. A copy would drift the moment the workflow
    changed, which is the mistake already made once in this project with
    `aggregate_provider_scores`.
    """

    @staticmethod
    def _classifier_source():
        import re

        text = WORKFLOW.read_text(encoding="utf-8")
        match = re.search(r"python3 - <<'PY'\n(.*?)\n          PY", text, re.S)
        assert match, (
            "the classifier heredoc was not found in the workflow. If the step was "
            "restructured, update this extraction - otherwise the failure semantics below "
            "are no longer being tested at all."
        )
        return "\n".join(
            line[10:] if line.startswith(" " * 10) else line
            for line in match.group(1).splitlines()
        )

    def _run(self, tmp_path, body):
        import subprocess
        import sys

        script = tmp_path / "classify.py"
        script.write_text(self._classifier_source(), encoding="utf-8")
        response = tmp_path / "response.json"
        if body is not None:
            response.write_text(body, encoding="utf-8")
        return subprocess.run(
            [sys.executable, str(script)], cwd=tmp_path,
            capture_output=True, text=True,
        )

    def test_all_feeds_healthy_passes(self, tmp_path):
        result = self._run(tmp_path, '[{"slug":"urlhaus","status":"success"}]')
        assert result.returncode == 0, result.stdout + result.stderr

    def test_one_failed_feed_does_NOT_fail_the_workflow(self, tmp_path):
        """The whole point. This is the normal path, not an incident."""
        body = ('[{"slug":"a","status":"success"},'
                '{"slug":"b","status":"failed","error":"429 Too Many Requests"},'
                '{"slug":"c","status":"success"}]')
        result = self._run(tmp_path, body)
        assert result.returncode == 0, (
            "a single failing feed turned the workflow red. That happens routinely and "
            "would make the badge useless:\n" + result.stdout + result.stderr
        )
        assert "warning" in result.stdout.lower(), (
            "the failing feed was not surfaced as a warning, so it is invisible"
        )

    def test_every_feed_failing_DOES_fail_the_workflow(self, tmp_path):
        """Systemic: an expired cron secret, a dead database, a bad deploy."""
        result = self._run(
            tmp_path, '[{"slug":"a","status":"failed"},{"slug":"b","status":"error"}]')
        assert result.returncode == 1, (
            "every feed reported failure and the workflow stayed green:\n" + result.stdout
        )

    def test_a_wrapped_response_is_understood(self, tmp_path):
        """The response shape is not pinned by a schema, so both forms are accepted."""
        assert self._run(
            tmp_path, '{"feeds":[{"slug":"a","status":"failed"},'
                      '{"slug":"b","status":"success"}]}').returncode == 0
        assert self._run(
            tmp_path, '{"results":[{"slug":"a","status":"failed"}]}').returncode == 1

    def test_an_unrecognised_shape_is_reported_but_not_failed(self, tmp_path):
        """The endpoint answered 2xx. Guessing its meaning would be worse than saying so."""
        result = self._run(tmp_path, '{"ok":true,"count":5}')
        assert result.returncode == 0
        assert "notice" in result.stdout.lower()

    def test_a_malformed_body_fails(self, tmp_path):
        assert self._run(tmp_path, "not json at all").returncode == 1

    def test_a_missing_body_fails(self, tmp_path):
        """curl wrote no file, which means the request did not complete."""
        assert self._run(tmp_path, None).returncode == 1

    def test_an_empty_feed_list_does_not_fail(self, tmp_path):
        """0 of 0 failed is not "every feed failed" - guard against a divide-by-zero
        style off-by-one in the systemic check."""
        assert self._run(tmp_path, "[]").returncode == 0

    def test_no_data_is_not_treated_as_failure(self, tmp_path):
        """`BaseFeed.run()` distinguishes these deliberately, so the workflow must too."""
        assert self._run(tmp_path, '[{"slug":"a","status":"no_data"}]').returncode == 0

    def test_the_job_has_a_timeout(self):
        """GitHub's default is 360 minutes - a hung curl against a spun-down instance
        could sit for hours, and on a private repo that eats the monthly allowance."""
        import re

        text = WORKFLOW.read_text(encoding="utf-8")
        match = re.search(r"timeout-minutes:\s*(\d+)", text)
        assert match, "the sync job has no timeout-minutes, so it inherits GitHub's 360"
        assert int(match.group(1)) <= 30, (
            f"timeout-minutes is {match.group(1)}; the sync window is ~15 minutes, so "
            "anything much above that is waiting on a hang rather than on work"
        )


class TestTheCronParserAcceptsEverythingCorrect:
    """The parser must not be stricter than the constraint it enforces.

    Its first version understood only `*/N` and raised on `17 0,6,12,18 * * *`, which is
    evenly spaced and correct. Rejecting a valid schedule pushes people toward a workaround
    rather than the right answer.
    """

    @pytest.mark.parametrize("expression,expected", [
        ("17 */6 * * *", 6),
        ("17 0,6,12,18 * * *", 6),
        ("0 */12 * * *", 12),
        ("0 0,12 * * *", 12),
        ("30 */4 * * *", 4),
        ("0 * * * *", 1),
        ("0 3 * * *", 24),
    ], ids=["step-6", "enumerated-6", "step-12", "enumerated-12", "step-4",
            "hourly", "once-daily"])
    def test_evenly_spaced_schedules_reduce(self, expression, expected):
        assert _cron_interval_hours(expression) == expected

    def test_enumerated_and_step_forms_agree(self):
        """They describe the same schedule, so they must reduce identically."""
        assert _cron_interval_hours("17 0,6,12,18 * * *") == \
            _cron_interval_hours("17 */6 * * *")

    def test_the_midnight_wraparound_is_counted(self):
        """`0,6,12` looks like every 6 hours within the day and is not.

        The real worst case is the 12-hour overnight gap from 12:00 to 00:00. Omitting the
        wraparound would accept it as a 6-hour schedule and the window check would then be
        calibrated against a gap half the true size - silently under-reporting exactly what
        it exists to catch.
        """
        with pytest.raises(AssertionError, match="uneven gaps"):
            _cron_interval_hours("0 0,6,12 * * *")

    def test_a_genuinely_uneven_schedule_still_raises(self):
        with pytest.raises(AssertionError, match="uneven gaps"):
            _cron_interval_hours("0 9,17,21,23 * * *")

    def test_the_uneven_message_names_the_worst_case_gap(self):
        """So the reader can act on it rather than only being refused."""
        with pytest.raises(AssertionError) as excinfo:
            _cron_interval_hours("0 9,17,21,23 * * *")
        message = str(excinfo.value)
        assert "worst-case" in message.lower()
        assert "10h" in message, f"the largest gap (9->17 next day is 10h) is not named: {message}"

    def test_an_unparseable_hour_field_says_so(self):
        with pytest.raises(AssertionError, match="does not understand"):
            _cron_interval_hours("0 9-17 * * *")

    def test_a_malformed_expression_is_rejected(self):
        with pytest.raises(AssertionError, match="expected 5 cron fields"):
            _cron_interval_hours("*/6 * * *")
