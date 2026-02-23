"""Rate limiting utilities for external API calls."""

import time
import asyncio
from collections import defaultdict
from typing import Optional

import redis
from app.config import settings


class RateLimiter:
    """Token bucket rate limiter backed by Redis."""

    def __init__(self, redis_url: Optional[str] = None):
        self._redis_url = redis_url or settings.REDIS_URL
        self._redis = None
        self._local_limits = defaultdict(lambda: {"tokens": 10, "last_refill": time.time()})

    @property
    def redis_client(self):
        if self._redis is None:
            try:
                self._redis = redis.from_url(self._redis_url)
                self._redis.ping()
            except Exception:
                self._redis = None
        return self._redis

    def _check_local(self, key: str, max_requests: int, window_seconds: int) -> bool:
        """Fallback local rate limiting when Redis is unavailable."""
        now = time.time()
        limit = self._local_limits[key]
        elapsed = now - limit["last_refill"]
        refill = elapsed * (max_requests / window_seconds)
        limit["tokens"] = min(max_requests, limit["tokens"] + refill)
        limit["last_refill"] = now

        if limit["tokens"] >= 1:
            limit["tokens"] -= 1
            return True
        return False

    def check_rate_limit(self, key: str, max_requests: int, window_seconds: int) -> bool:
        """Check if a request is within rate limits. Returns True if allowed."""
        client = self.redis_client
        if client is None:
            return self._check_local(key, max_requests, window_seconds)

        try:
            pipe = client.pipeline()
            now = time.time()
            window_key = f"ratelimit:{key}"

            pipe.zremrangebyscore(window_key, 0, now - window_seconds)
            pipe.zcard(window_key)
            pipe.zadd(window_key, {str(now): now})
            pipe.expire(window_key, window_seconds)
            results = pipe.execute()

            current_count = results[1]
            return current_count < max_requests
        except Exception:
            return self._check_local(key, max_requests, window_seconds)

    async def wait_for_slot(self, key: str, max_requests: int, window_seconds: int):
        """Async wait until rate limit slot is available."""
        while not self.check_rate_limit(key, max_requests, window_seconds):
            await asyncio.sleep(1.0)


rate_limiter = RateLimiter()
