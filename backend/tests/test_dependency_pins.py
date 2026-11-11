"""The pinned dependency set, and the CI job that installs it (#136).

Every existing environment already has greenlet, so no import-level test can see it
go missing. These check the files a clean install is built from.
"""

import pathlib
import re

ROOT = pathlib.Path(__file__).resolve().parents[2]
REQUIREMENTS = ROOT / "backend" / "requirements.txt"
WORKFLOW = ROOT / ".github" / "workflows" / "tests.yml"
RENDER_YAML = ROOT / "render.yaml"


def _requirement(name):
    """The requirement line for `name`, comments stripped, or None."""
    for raw in REQUIREMENTS.read_text(encoding="utf-8").splitlines():
        line = raw.split("#", 1)[0].strip()
        if re.match(rf"{re.escape(name)}\s*(\[|==|>=|~=|$)", line, re.IGNORECASE):
            return line
    return None


def test_sqlalchemy_carries_the_asyncio_extra():
    """SQLAlchemy 2.1 installs greenlet only through the asyncio extra.

    Without it the async engine raises at import, and every deploy of 2.1.6 without
    the extra failed from 2026-11-03.
    """
    line = _requirement("sqlalchemy")
    assert line is not None, "no sqlalchemy line found in requirements.txt"
    assert re.match(r"sqlalchemy\[[^\]]*\basyncio\b[^\]]*\]", line, re.IGNORECASE), (
        f"{line!r}: the async engine needs greenlet, which SQLAlchemy 2.1 installs only "
        "via the [asyncio] extra"
    )


def _render_python_version():
    text = RENDER_YAML.read_text(encoding="utf-8")
    match = re.search(r"-\s*key:\s*PYTHON_VERSION\s*\n\s*value:\s*['\"]?([\d.]+)", text)
    assert match, "PYTHON_VERSION not found in render.yaml"
    return match.group(1)


def test_ci_runs_the_production_python():
    text = WORKFLOW.read_text(encoding="utf-8")
    versions = re.findall(
        r"(?:python-version:\s*['\"]?|container:\s*(?:image:\s*)?['\"]?python:)([\d.]+)", text
    )
    assert versions, "no Python version found in the tests workflow"
    assert set(versions) == {_render_python_version()}, (
        f"tests.yml runs Python {versions}, render.yaml deploys "
        f"{_render_python_version()}"
    )


def test_ci_installs_from_the_pins_and_nothing_else():
    """A hand-installed package in CI would mask a missing pin, as greenlet was."""
    text = WORKFLOW.read_text(encoding="utf-8")
    installs = [
        line.split("#", 1)[0].strip()
        for line in text.splitlines()
        if "pip install" in line.split("#", 1)[0]
    ]
    assert installs, "the tests workflow has no pip install step"
    for line in installs:
        assert re.search(r"pip install( --[\w-]+)* -r requirements-dev\.txt$", line), (
            f"{line!r}: CI must install exactly requirements-dev.txt"
        )
