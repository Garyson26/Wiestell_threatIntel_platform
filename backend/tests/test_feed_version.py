import pytest

from backend.app.utils.feed_version import compare, read_version


def test_parses_three_parts():
    assert read_version("1.4.2") == (1, 4, 2)


def test_orders_versions():
    assert compare("1.4.2", "1.10.0") == -1


def test_rejects_garbage():
    with pytest.raises(ValueError):
        read_version("banana")
