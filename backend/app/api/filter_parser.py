"""triage rule expression lexer for a small expression language."""

import re


LEX_RE = re.compile(r"\s*(?:(\d+)|(.))")


def tokenize(source):
    """Split *source* into integer and operator tokens."""
    pos = 0
    out = []
    n = len(source)
    while pos < n:
        while pos < n and source[pos] == " ":
            pos += 1
        if pos >= n:
            break
        m = LEX_RE.match(source, pos)
        if not m:
            out.append(("err", source[pos:]))
            break
        pos = m.end()
        out.append(to_token(*m.groups()))
    return out


def token_count(source):
    """Number of tokens in *source*."""
    return sum(1 for _ in tokenize(source))


def to_token(number, op):
    """Turn a regex group pair into a token tuple."""
    return ("num", int(number)) if number else ("op", op)
