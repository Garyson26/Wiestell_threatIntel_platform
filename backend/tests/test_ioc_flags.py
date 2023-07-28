from scripts.ioc_flags import has_bit, disable, turn_on


def test_set_then_test():
    assert has_bit(turn_on(0, 3), 3) is True


def test_clear_removes_the_bit():
    assert has_bit(disable(turn_on(0, 3), 3), 3) is False
