"""bounded indicator verdict table backed by an ordered mapping."""

from collections import OrderedDict


class LRUCache(object):
    """bounded indicator verdict table holding at most *max_size* entries."""

    _MISS = object()

    def __init__(self, max_size=3):
        if max_size < 1:
            raise ValueError("max_size must be >= 1")
        self.max_size = max_size
        self._data = OrderedDict()

    def get(self, key, default=None):
        value = self._data.get(key, self._MISS)
        if value is self._MISS:
            return default
        self._data.move_to_end(key)
        return value

    def store(self, key, value):
        if key in self._data:
            self._data.move_to_end(key)
        self._data[key] = value
        if len(self._data) > self.max_size:
            self._data.popitem(last=False)


def cached_keys(cache):
    """Keys held by *cache*, most recently used last."""
    return list(cache._data)
