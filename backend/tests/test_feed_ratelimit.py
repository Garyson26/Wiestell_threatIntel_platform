from backend.app.feed_ratelimit import RateLimiter


def test_allows_initial_burst():
    bucket = RateLimiter(rate=1, capacity=3)
    assert all(bucket.take() for _ in range(3))


def test_denies_once_drained():
    bucket = RateLimiter(rate=1, capacity=1)
    assert bucket.take() is True
    assert bucket.take() is False
