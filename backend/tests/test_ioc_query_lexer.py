from backend.app.models.ioc_query_lexer import scan


def test_tokenizes_integers():
    assert scan("12 + 3") == [("num", 12), ("op", "+"), ("num", 3)]


def test_handles_empty_source():
    assert scan("") == []
