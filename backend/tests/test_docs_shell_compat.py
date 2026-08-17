"""Every documented shell command must be runnable in the shell the owner actually uses.

CLAUDE.md states the rule: "Any command in these docs that sets an environment variable
needs both forms." This enforces it, plus the broader property behind it.

**Three documented commands have already failed against the real environment**, which is
why this is a test and not a convention:

  * `VAR=value python ...`      — a PARSE ERROR in PowerShell, not a working variant
  * `--proxy-headers=false`     — uvicorn rejects it; the disable form is `--no-proxy-headers`
  * `cd backend && pytest`      — `&&` is "not a valid statement separator" in PS 5.1

The common shape is that each **fails outright rather than degrading**, and each was
discovered mid-task rather than while being written. A snippet that cannot run where it is
meant to run is worse than no snippet, because the reader is by then following a runbook.
The rescore is the sharpest case: an hour-plus job against a shared host, so a syntax
failure discovered partway through costs the whole run.

A bash-only construct is ACCEPTABLE when a `powershell` block sits beside it — that is the
"both forms" rule, not a violation of it. So the check is not "no bash syntax anywhere"
but "no bash syntax without its PowerShell counterpart nearby".

Per the CLAUDE.md extraction rule, the block scanner asserts what it FOUND before
asserting what it did not find: a scanner that silently matches no code blocks would make
every assertion below pass vacuously.
"""

import re
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parents[2]

#: Constructs that FAIL in Windows PowerShell 5.1 rather than behaving differently.
FATAL = [
    (re.compile(r"&&"), "`&&` is a parse error in PowerShell 5.1"),
    (re.compile(r"\|\|"), "`||` is a parse error in PowerShell 5.1"),
    (re.compile(r"^\s*export\s+[A-Za-z_]"), "`export` is not a PowerShell cmdlet"),
    (re.compile(r"^\s*[A-Z_][A-Z0-9_]*=[^\s]+\s+[A-Za-z]"),
     "inline `VAR=value cmd` prefix is a parse error in PowerShell"),
    (re.compile(r"/dev/null"), "`/dev/null` does not exist on Windows (PowerShell: `$null`)"),
    (re.compile(r"\brm\s+-[rf]"), "`rm -rf` — `-rf` is not a PowerShell flag"),
]

#: Fence languages that represent something a human is meant to TYPE at a shell.
SHELL_LANGS = {"bash", "sh", "shell", "console", "zsh"}

#: How far from a bash block a `powershell` block may sit and still count as its pair.
PAIR_WINDOW_LINES = 25


def _markdown_files():
    for path in sorted(REPO.rglob("*.md")):
        if "node_modules" in path.parts or ".git" in path.parts:
            continue
        yield path


def _code_blocks(path):
    """Yield (lang, start_line, [body lines]) for every fenced block in a file."""
    lines = path.read_text(encoding="utf-8", errors="replace").splitlines()
    lang = None
    start = 0
    body = []
    for i, line in enumerate(lines, 1):
        fence = re.match(r"^\s*```(\w*)", line)
        if fence:
            if lang is None:
                lang, start, body = (fence.group(1) or "none"), i, []
            else:
                yield lang, start, body
                lang = None
        elif lang is not None:
            body.append(line)


def _all_blocks():
    out = []
    for path in _markdown_files():
        for lang, start, body in _code_blocks(path):
            out.append((path, lang, start, body))
    return out


class TestTheScannerWorks:
    """Non-emptiness first — otherwise everything below passes for the wrong reason."""

    def test_it_finds_markdown_files(self):
        files = list(_markdown_files())
        assert len(files) >= 5, f"only {len(files)} markdown files found; scanner is broken"

    def test_it_finds_shell_blocks(self):
        blocks = [b for b in _all_blocks() if b[1] in SHELL_LANGS]
        assert len(blocks) >= 10, (
            f"only {len(blocks)} shell code blocks found across the docs. The fence parser "
            "has probably stopped matching, which makes the compatibility test vacuous."
        )

    def test_it_finds_the_paired_powershell_blocks(self):
        """The 'both forms' rule is in use, so its blocks must be detectable."""
        ps = [b for b in _all_blocks() if b[1] == "powershell"]
        assert len(ps) >= 2, (
            f"found {len(ps)} powershell blocks; CLAUDE.md and DEPLOY_CHECKLIST.md both "
            "document one, so the parser is not seeing them"
        )


class TestNoDocumentedCommandIsUnrunnableOnWindows:
    def test_every_shell_block_is_powershell_safe_or_paired(self):
        powershell_lines = {}
        for path, lang, start, body in _all_blocks():
            if lang == "powershell":
                powershell_lines.setdefault(path, []).append(start)

        violations = []
        for path, lang, start, body in _all_blocks():
            if lang not in SHELL_LANGS:
                continue
            nearby = powershell_lines.get(path, [])
            paired = any(abs(p - start) <= PAIR_WINDOW_LINES for p in nearby)
            if paired:
                continue  # documented in both forms -- this is the rule, not a breach
            for offset, line in enumerate(body):
                if line.strip().startswith("#"):
                    continue
                for pattern, why in FATAL:
                    if pattern.search(line):
                        rel = path.relative_to(REPO).as_posix()
                        violations.append(
                            f"{rel}:{start + offset + 1}  {why}\n         {line.strip()[:88]}"
                        )
                        break

        assert not violations, (
            "these documented commands cannot run in Windows PowerShell 5.1, the owner's "
            "shell, and fail outright rather than degrading:\n\n  "
            + "\n  ".join(violations)
            + "\n\nEither rewrite them shell-agnostically (separate lines instead of `&&`) "
              "or add a `powershell` block beside them, per the 'both forms' rule in "
              "CLAUDE.md."
        )


class TestTheRescoreRunbookCarriesBothForms:
    """Singled out because it is the highest-cost command in the repo.

    An hour-plus job against a shared host, run by the owner from Windows at deploy time.
    A syntax failure found mid-runbook is far worse than one found now.
    """

    def test_the_rescore_script_documents_a_powershell_invocation(self):
        doc = (REPO / "scripts" / "rescore_corpus.py").read_text(encoding="utf-8")
        assert "$env:DATABASE_URL" in doc, (
            "rescore_corpus.py's docstring lost its PowerShell invocation. The bash form "
            "`VAR=value python ...` is a PARSE ERROR in the shell the owner runs it from."
        )
        assert "PARSE ERROR" in doc, (
            "the docstring no longer explains WHY the bash form is not a fallback; without "
            "that, someone will 'simplify' it back to one form"
        )

    @pytest.mark.parametrize("flag", ["--dry-run"])
    def test_the_powershell_form_runs_the_dry_run_first(self, flag):
        doc = (REPO / "scripts" / "rescore_corpus.py").read_text(encoding="utf-8")
        ps_section = doc[doc.index("$env:DATABASE_URL"):]
        assert flag in ps_section[:600], (
            "the PowerShell invocation should demonstrate --dry-run, not the write pass"
        )
