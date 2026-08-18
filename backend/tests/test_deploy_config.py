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
            "RESEND_API_KEY", "MAXMIND_LICENSE_KEY", "REDIS_URL",
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


class TestDependabotConfig:
    """Grouping is the point, so the config's shape is worth asserting.

    Unconfigured, Dependabot opens one PR per advisory - dozens at this repository's alert
    volume. The risk being managed is alert fatigue: once the feed is ignored, the next
    genuinely serious advisory lands in a stream nobody reads. If this file were deleted or
    its grouping removed, that would revert silently, so it is pinned.
    """

    CONFIG = ROOT / ".github" / "dependabot.yml"

    def test_the_config_exists(self):
        assert self.CONFIG.exists(), (
            "no .github/dependabot.yml. Without it Dependabot opens one PR per advisory, "
            "which at this alert volume trains reviewers to ignore the feed."
        )

    def test_both_ecosystems_are_rooted_where_the_manifests_are(self):
        """A root-level entry would find no manifest and report nothing, silently."""
        text = self.CONFIG.read_text(encoding="utf-8")
        assert "package-ecosystem: pip" in text
        assert "package-ecosystem: npm" in text
        assert "directory: /backend" in text, "pip must be rooted at /backend"
        assert "directory: /frontend" in text, "npm must be rooted at /frontend"
        # And those really are the manifest locations.
        assert (ROOT / "backend" / "requirements.txt").exists()
        assert (ROOT / "frontend" / "package.json").exists()

    def test_patch_and_minor_updates_are_grouped(self):
        text = self.CONFIG.read_text(encoding="utf-8")
        assert "groups:" in text, "grouping removed - see this class's docstring"
        assert text.count("groups:") >= 2, (
            "only one ecosystem groups its updates; both should"
        )
        for update_type in ("minor", "patch"):
            assert f"- {update_type}" in text, f"{update_type} updates are not grouped"

    def test_the_schedule_is_not_daily(self):
        """Daily becomes background noise, and no advisory here has an exposure window
        that differs meaningfully at 1 day versus 7."""
        text = self.CONFIG.read_text(encoding="utf-8")
        assert "interval: daily" not in text, (
            "a daily schedule reintroduces the noise the grouping exists to prevent"
        )
        assert "interval: weekly" in text

    def test_the_framework_majors_stay_out_of_the_grouped_pr(self):
        """A framework bump beside a security bump makes a regression unattributable.

        That is why Spec 6 §1 upgraded six packages and left these alone; the config
        should not undo it by sweeping a major into a grouped merge.
        """
        text = self.CONFIG.read_text(encoding="utf-8")
        for name in ("fastapi", "starlette", "sqlalchemy", "pydantic", "aiomysql", "next"):
            assert f"dependency-name: {name}" in text, (
                f"{name} major updates are not held out of the grouped PR"
            )

    def test_the_comment_explains_the_duplicate_pip_alerts(self):
        """Otherwise the next reader removes the `-r` include to "fix" the duplication.

        That include is what makes a fresh clone bootstrap in one command (Spec 4,
        re-verified Spec 6 §1), and duplicate alerts are the cheaper problem.
        """
        text = self.CONFIG.read_text(encoding="utf-8")
        assert "requirements-dev.txt" in text and "-r requirements.txt" in text, (
            "the config does not explain why pip advisories appear twice, so someone will "
            "eventually remove the include to suppress them"
        )
        assert "intentional" in text.lower() or "INTENTIONAL" in text

    def test_the_dev_include_is_still_present(self):
        """The property the comment above is protecting.

        Matched against UNCOMMENTED lines only. The first version of this test searched the
        raw text, so commenting the include out - `# -r requirements.txt` - still satisfied
        it. Found by mutation-testing this very guard, which is the eighth time that trap
        has appeared in this project and the reason for the standing rule in CLAUDE.md.
        The file also *documents* the include in its header comment, so raw matching was
        guaranteed to pass here no matter what the directive said.
        """
        dev = (ROOT / "backend" / "requirements-dev.txt").read_text(encoding="utf-8")
        directives = [
            line.strip()
            for line in dev.splitlines()
            if line.strip() and not line.strip().startswith("#")
        ]
        assert any(d.startswith("-r requirements.txt") for d in directives), (
            "requirements-dev.txt no longer includes requirements.txt as an active "
            "directive, so `pip install -r requirements-dev.txt && python -m pytest` no "
            f"longer bootstraps a fresh clone in one command. Active lines: {directives}"
        )


class TestTheAsyncDSNFailsAtBootNotAtFirstQuery:
    """`DATABASE_ASYNC_URL` is derived by a LITERAL prefix replace.

    Only `mysql+pymysql://` is rewritten. A DSN written `mysql://` or `mysql+mysqldb://`
    falls through unchanged and hands the async engine a synchronous driver — which does
    not fail until the first `await session.execute(...)`, by which point the service is
    up, healthy and serving errors. Measured across four shapes on 2026-08-17; two fell
    through silently.
    """

    def _settings_with(self, dsn):
        """Construct a Settings instance directly — do NOT reload the module.

        `importlib.reload(app.config)` replaces the module-level `settings` singleton,
        and every other module holds a `from app.config import settings` reference to the
        OLD object. Fixture state applied to that object (the GeoIP path, for one) is
        then silently discarded, which made `test_a_correct_deployment_reports_nothing`
        fail in the full suite while passing alone. Instantiating exercises the same
        `model_post_init` validator with no global mutation.
        """
        from app.config import Settings

        return Settings(DATABASE_URL=dsn, SECRET_KEY="x" * 40, DATABASE_ASYNC_URL="")

    def test_a_pymysql_dsn_derives_correctly(self):
        cfg = self._settings_with("mysql+pymysql://u:p@h/db")
        assert cfg.DATABASE_ASYNC_URL == "mysql+aiomysql://u:p@h/db"

    def test_a_query_string_survives_the_rewrite(self):
        cfg = self._settings_with("mysql+pymysql://u:p@h/db?ssl_ca=/x.pem")
        assert cfg.DATABASE_ASYNC_URL.endswith("?ssl_ca=/x.pem")
        assert cfg.DATABASE_ASYNC_URL.startswith("mysql+aiomysql://")

    @pytest.mark.parametrize("dsn", [
        "mysql://u:p@h/db",
        "mysql+mysqldb://u:p@h/db",
        "postgresql://u:p@h/db",
    ])
    def test_a_dsn_that_cannot_be_rewritten_raises_at_import(self, dsn):
        with pytest.raises(Exception) as exc:
            self._settings_with(dsn)
        assert "aiomysql" in str(exc.value), (
            "the error does not name the driver, so an operator reading it cannot tell "
            "what to change"
        )

    def test_the_global_settings_object_is_untouched(self):
        """The reason this class instantiates rather than reloads.

        A reload swaps `app.config.settings`, and modules holding a reference to the old
        object lose any fixture state applied to it — which is exactly how the first
        version of these tests broke test_process_model in the full suite while passing
        in isolation.
        """
        from app.config import settings

        before = settings.DATABASE_ASYNC_URL
        self._settings_with("mysql+pymysql://other:other@elsewhere/db")
        assert settings.DATABASE_ASYNC_URL == before


class TestRenderYamlDeployShape:
    """Blueprint facts that are expensive to get wrong and cheap to assert."""

    def _render_yaml(self):
        import pathlib

        import yaml

        path = pathlib.Path(__file__).resolve().parents[2] / "render.yaml"
        return yaml.safe_load(path.read_text(encoding="utf-8")), path.read_text(encoding="utf-8")

    def test_every_service_is_in_frankfurt(self):
        """Region is IMMUTABLE after creation — recreating is the only way to change it."""
        data, _ = self._render_yaml()
        regions = {s["name"]: s.get("region") for s in data["services"]}
        assert regions, "no services parsed"
        wrong = {n: r for n, r in regions.items() if r != "frankfurt"}
        assert not wrong, f"these services are not in frankfurt: {wrong}"

    def test_the_backend_declares_the_python_runtime(self):
        """backend/Dockerfile EXISTS, so a Docker-built service would skip buildCommand
        entirely — and with it the GeoLite2 download."""
        data, _ = self._render_yaml()
        backend = next(s for s in data["services"] if s["name"] == "wiestell-backend")
        assert backend.get("runtime") == "python", (
            "the backend no longer declares runtime: python. If Render builds from "
            "backend/Dockerfile instead, buildCommand never runs, download_geolite2.py "
            "never executes, and GeoIP is silently unavailable for the whole IP population."
        )

    def test_the_migration_is_not_run_from_the_build_command(self):
        """Removed 2026-08-17: redundant (§2 runs it from a developer machine) AND it
        swallowed failure, so a failed migration produced a successful deploy."""
        data, _ = self._render_yaml()
        backend = next(s for s in data["services"] if s["name"] == "wiestell-backend")
        build = backend.get("buildCommand", "")
        lines = [
            ln.strip() for ln in build.splitlines()
            if ln.strip() and not ln.strip().startswith("#")
        ]
        assert lines, "buildCommand parsed as empty; the check would be vacuous"
        offenders = [ln for ln in lines if ln.startswith("alembic")]
        assert not offenders, (
            f"alembic runs in the build command again: {offenders}. Migrations run from "
            "a developer machine per DEPLOY_CHECKLIST §2, and a build-time migration "
            "that fails open deploys against an unmigrated database."
        )

    def test_no_dead_fromservice_reference(self):
        """It named `sentinel-backend`; the backend is `wiestell-backend`."""
        data, raw = self._render_yaml()
        names = {s["name"] for s in data["services"]}
        for service in data["services"]:
            for var in service.get("envVars") or []:
                ref = (var.get("fromService") or {}).get("name")
                if ref:
                    assert ref in names, (
                        f"{service['name']}.{var.get('key')} references service {ref!r}, "
                        f"which does not exist. Declared services: {sorted(names)}"
                    )

    def test_no_sensitive_variable_carries_a_committed_literal(self):
        data, _ = self._render_yaml()
        sensitive = ("KEY", "SECRET", "TOKEN", "PASSWORD", "DATABASE_URL")
        offenders = []
        for service in data["services"]:
            for var in service.get("envVars") or []:
                key = var.get("key", "")
                if any(marker in key.upper() for marker in sensitive):
                    if "value" in var:
                        offenders.append(f"{service['name']}.{key}")
        assert not offenders, (
            f"these sensitive variables carry a committed literal value: {offenders}. "
            "They must use sync: false or generateValue: true."
        )


class TestTheFreePlanSizingHoldsTogether:
    """`plan: free` is not only a cost setting — four decisions are sized for it.

    Confirmed 2026-08-17. Each of these was chosen against a free instance's limits, and
    raising the plan without revisiting them together is how they drift apart:

      --workers 1            six single-process subsystems (CLAUDE.md)
      --no-proxy-headers     uvicorn's proxy middleware would fight deps.py::_client_ip
      pool sizes             a SHARED MySQL account allowance, not a per-app one
      ENRICHMENT_CONCURRENCY third-party rate limits are per API key, not per task
      previewsEnabled: false 750 instance-hours/month is account-wide
    """

    def _backend(self):
        import pathlib

        import yaml

        path = pathlib.Path(__file__).resolve().parents[2] / "render.yaml"
        data = yaml.safe_load(path.read_text(encoding="utf-8"))
        return next(s for s in data["services"] if s["name"] == "wiestell-backend")

    def test_the_backend_is_on_the_free_plan(self):
        assert self._backend().get("plan") == "free"

    def test_previews_are_disabled(self):
        """Free instance-hours are one account-wide pool; a preview spends production's."""
        assert self._backend().get("previewsEnabled") is False, (
            "previews are not explicitly disabled. Off is Render's default, but the "
            "default is not the reason — every preview service draws from the same "
            "750-hour monthly pool the production service needs."
        )

    def test_the_start_command_declares_one_worker_and_no_proxy_headers(self):
        cmd = self._backend().get("startCommand", "")
        assert "--workers 1" in cmd, (
            "--workers 1 is gone from render.yaml. Six subsystems assume one process "
            "per instance; main.py refuses to boot above 1, so this would be a crash "
            "loop rather than a silent degradation — but declare it anyway."
        )
        assert "--no-proxy-headers" in cmd, (
            "--no-proxy-headers is gone. uvicorn's proxy_headers defaults to TRUE, and "
            "its X-Forwarded-For handling would fight deps.py::_client_ip (finding R-05). "
            "Note the disable form is --no-proxy-headers; --proxy-headers=false is "
            "invalid and uvicorn refuses to start."
        )

    def test_start_sh_agrees_with_render_yaml(self):
        """Two start paths, and they must not disagree."""
        import pathlib

        start = (pathlib.Path(__file__).resolve().parents[1] / "start.sh").read_text(
            encoding="utf-8"
        )
        for flag in ("--workers 1", "--no-proxy-headers"):
            assert flag in start, f"{flag} missing from start.sh"

    def test_the_connection_pools_are_unchanged(self):
        """Both engines total 5, so one process holds at most 10 connections.

        The values are NOT symmetric and it is worth stating which is which: the ASYNC
        engine — the one serving requests — is 2 + 3, and the sync engine used by scripts
        and Alembic is 3 + 2. Both sum to 5 against a shared MySQL account allowance.
        """
        import inspect

        from app import database

        source = inspect.getsource(database)
        assert "pool_size=2" in source and "max_overflow=3" in source, (
            "the async pool moved off 2 + 3"
        )
        assert "pool_size=3" in source and "max_overflow=2" in source, (
            "the sync pool moved off 3 + 2"
        )

    def test_the_enrichment_semaphore_is_still_five(self):
        from app.services.enrichment_engine import ENRICHMENT_CONCURRENCY

        assert ENRICHMENT_CONCURRENCY == 5, (
            f"ENRICHMENT_CONCURRENCY is {ENRICHMENT_CONCURRENCY}, expected 5. It is "
            "module-level, so the bound is process-wide; raising it multiplies "
            "third-party calls in flight against per-key rate limits, and on 0.1 CPU "
            "the WHOIS executor cannot absorb the fan-out."
        )

    def test_no_render_cron_job_is_declared(self):
        """Cron jobs are a paid feature; the live path is external GitHub Actions."""
        import pathlib

        import yaml

        path = pathlib.Path(__file__).resolve().parents[2] / "render.yaml"
        data = yaml.safe_load(path.read_text(encoding="utf-8"))
        assert not data.get("jobs"), (
            "a Render cron job is declared, but cron jobs are not available on the free "
            "plan. The live background path is the GitHub Actions schedule calling "
            "POST /api/v1/feeds/sync-all."
        )


class TestTheBlueprintIsValidForAFreeInstance:
    """Three things the Blueprint was rejected or degraded for, 2026-08-17."""

    def _blueprint(self):
        import pathlib

        import yaml

        path = pathlib.Path(__file__).resolve().parents[2] / "render.yaml"
        return yaml.safe_load(path.read_text(encoding="utf-8"))

    def _backend(self):
        return next(
            s for s in self._blueprint()["services"] if s["name"] == "wiestell-backend"
        )

    def test_no_service_declares_a_disk(self):
        """Persistent disks are not available on free instances — the actual rejection.

        And it would have been wrong even on a paid plan: the disk mounted at
        /opt/render/project/src/backend/data, byte-identical to the directory
        GEOIP_DB_PATH points into, which is where download_geolite2.py writes AT BUILD
        TIME. The disk would mount over the freshly-built .mmdb and hide it, so GeoIP
        would be missing despite a correct download — visible only as
        `geoip_database_missing` on the admin-gated /cron-status.
        """
        offenders = [s["name"] for s in self._blueprint()["services"] if s.get("disk")]
        assert not offenders, (
            f"these services declare a disk: {offenders}. Free instances cannot have "
            "one, and at the GeoIP path it would shadow the build-time download."
        )

    def test_the_geoip_path_is_not_a_mount_point_for_anything(self):
        """The shadowing hazard, stated as a property rather than a one-off fix."""
        backend = self._backend()
        geoip = next(
            (v.get("value") for v in backend.get("envVars", [])
             if v.get("key") == "GEOIP_DB_PATH"),
            None,
        )
        assert geoip, "GEOIP_DB_PATH is not declared"
        mounts = [
            (s.get("disk") or {}).get("mountPath")
            for s in self._blueprint()["services"]
        ]
        for mount in filter(None, mounts):
            assert not geoip.startswith(mount.rstrip("/") + "/"), (
                f"GEOIP_DB_PATH ({geoip}) sits under a disk mounted at {mount}. The "
                "database is written at BUILD time into the image; a runtime mount over "
                "that directory hides it."
            )

    def test_no_keep_alive_health_check_tuning(self):
        """A 50s health check means the instance NEVER sleeps.

        Free gives 750 instance-hours per month account-wide; never sleeping burns ~744
        of them. The four-window sync cadence is designed around the instance sleeping
        between windows, so this is a design contradiction, not just a cost one.
        """
        backend = self._backend()
        for key in ("healthCheckInterval", "healthCheckTimeout"):
            assert key not in backend, (
                f"{key} is declared again. It was removed because tuning it to keep the "
                "service warm defeats the sleep the free-plan hour budget and the sync "
                "cadence both assume. Render's defaults are correct."
            )
        assert backend.get("healthCheckPath") == "/health", (
            "healthCheckPath went with the tuning; the endpoint itself is still wanted"
        )

    def test_only_the_backend_service_is_declared(self):
        """A second free web service draws from the same 750-hour pool."""
        names = [s["name"] for s in self._blueprint()["services"]]
        assert names == ["wiestell-backend"], (
            f"expected only the backend, got {names}. The frontend deploys to Vercel; a "
            "Render frontend service would consume instance-hours the backend needs."
        )

    def test_the_removals_are_documented_in_place(self):
        """Deleted config with no trace invites someone re-adding it."""
        import pathlib

        raw = (pathlib.Path(__file__).resolve().parents[2] / "render.yaml").read_text(
            encoding="utf-8"
        )
        for marker in ("disk", "healthCheckInterval", "FRONTEND"):
            assert marker in raw, (
                f"{marker!r} vanished without a note. Each was removed for a reason that "
                "is not obvious from its absence, so the reason has to survive."
            )
