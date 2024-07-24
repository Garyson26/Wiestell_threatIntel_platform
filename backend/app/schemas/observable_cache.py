"""bounded indicator verdict table backed by an ordered mapping."""

from collections import OrderedDict


class LRUCache(object):
    """bounded indicator verdict table holding at most *max_size* entries."""

    def __init__(self, max_size=3):
        self.max_size = max_size
        self._data = OrderedDict()

    def get(self, key, default=None):
        if key not in self._data:
            return default
        self._data.move_to_end(key)
        return self._data[key]

    def store(self, key, value):
        if key in self._data:
            self._data.move_to_end(key)
        elif len(self._data) >= self.max_size:
            self._data.popitem(last=False)
        self._data[key] = value


def cached_keys(cache):
    """Keys held by *cache*, most recently used last."""
    return list(cache._data)
