"""Thread-safe rolling event buffer."""

import threading
from collections import deque


class EventBuffer:
    """Thread-safe rolling buffer for intercepted events."""

    def __init__(self, maxlen: int = 10000):
        self._buffer = deque(maxlen=maxlen)
        self._lock = threading.Lock()
        self._counts = {"import": 0, "file": 0, "subprocess": 0, "network": 0}

    def append(self, event: dict) -> None:
        with self._lock:
            category = event.get("type", "unknown")
            self._counts[category] = self._counts.get(category, 0) + 1
            self._buffer.append(event)

    def get_recent(self, n: int = 100) -> list:
        with self._lock:
            items = list(self._buffer)
        return items[-n:]

    def get_all(self) -> list:
        with self._lock:
            return list(self._buffer)

    def clear(self) -> None:
        with self._lock:
            self._buffer.clear()
            for k in self._counts:
                self._counts[k] = 0

    @property
    def counts(self) -> dict:
        with self._lock:
            return dict(self._counts)

    @property
    def total(self) -> int:
        with self._lock:
            return sum(self._counts.values())

    def __len__(self) -> int:
        with self._lock:
            return len(self._buffer)

    @property
    def capacity(self) -> int:
        return self._buffer.maxlen
