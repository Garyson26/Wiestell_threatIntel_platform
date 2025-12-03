from backend.app.models.query_tokens import tokenize


def test_tokenizes_integers():
    assert tokenize("12 + 3") == [("num", 12), ("op", "+"), ("num", 3)]


def test_handles_empty_source():
    assert tokenize("") == []
