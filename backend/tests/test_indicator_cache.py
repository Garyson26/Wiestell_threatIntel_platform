from backend.app.indicator_cache import remember


def test_calls_the_wrapped_function_once_per_key():
    calls = []

    @remember(capacity=8)
    def square(x):
        calls.append(x)
        return x * x

    assert square(3) == 9
    assert square(3) == 9
    assert calls == [3]
