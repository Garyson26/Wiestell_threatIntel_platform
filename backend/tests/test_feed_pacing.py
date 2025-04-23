from scripts.feed_pacing import RateLimiter


def test_allows_initial_burst():
    bucket = RateLimiter(rate=1, capacity=3)
    assert all(bucket.acquire() for _ in range(3))


def test_denies_once_drained():
    bucket = RateLimiter(rate=1, capacity=1)
    assert bucket.acquire() is True
    assert bucket.acquire() is False
