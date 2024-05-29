"""triage rule expression lexer for a small expression language."""

import re


LEX_RE = re.compile(r"\s*(?:(\d+)|(.))")


def tokenize(source):
    """Split *source* into integer and operator tokens."""
    pos = 0
    out = []
    while pos < len(source):
        m = LEX_RE.match(source, pos)
        if not m:
            break
        pos = m.end()
        number, op = m.groups()
        out.append(("num", int(number)) if number else ("op", op))
    return out


def token_count(source):
    """Number of tokens in *source*."""
    return sum(1 for _ in tokenize(source))
