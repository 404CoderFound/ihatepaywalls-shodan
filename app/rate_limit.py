from __future__ import annotations

import threading
import time


class FixedWindowLimiter:
    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._windows: dict[tuple[str, str], tuple[int, int]] = {}

    def clear(self) -> None:
        with self._lock:
            self._windows.clear()

    def allow(self, bucket: str, identity: str, limit: int, window_seconds: int = 60) -> tuple[bool, int]:
        window = int(time.time()) // window_seconds
        key = (bucket, identity)
        with self._lock:
            stored_window, count = self._windows.get(key, (window, 0))
            if stored_window != window:
                stored_window, count = window, 0
            count += 1
            self._windows[key] = (stored_window, count)
        return count <= limit, max(0, limit - count)
