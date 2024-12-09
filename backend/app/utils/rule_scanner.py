"""triage rule expression lexer for a small expression language."""

import re


SCAN_RE = re.compile(r"[ \t]*(?:(\d+)|(.))")


def tokenize(source):
    """Split *source* into integer and operator tokens."""
    pos = 0
    out = []
    while pos < len(source):
        m = SCAN_RE.match(source, pos)
        if not m:
            out.append(("err", source[pos:]))
            break
        pos = m.end()
        out.append(classify(*m.groups()))
    return out


def classify(number, op):
    """Turn a regex group pair into a token tuple."""
    return ("num", int(number)) if number else ("op", op)
