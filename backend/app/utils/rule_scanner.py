"""triage rule expression lexer for a small expression language."""

import re


SCAN_RE = re.compile(r"\s*(?:(\d+)|(.))")


def tokenize(source):
    """Split *source* into integer and operator tokens."""
    pos = 0
    out = []
    while pos < len(source):
        m = SCAN_RE.match(source, pos)
        if not m:
            break
        pos = m.end()
        number, op = m.groups()
        out.append(("num", int(number)) if number else ("op", op))
    return out
