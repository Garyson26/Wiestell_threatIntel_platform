from backend.app.feeds.config_pairs import parse_env


def test_skips_comments_and_blanks():
    assert parse_env("# note\n\nA=1\n") == {"A": "1"}


def test_ignores_lines_without_equals():
    assert parse_env("JUST_A_WORD\nB=2") == {"B": "2"}
