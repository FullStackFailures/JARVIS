"""Cooperative cancellation token with parent chaining."""

from __future__ import annotations

import threading
import time


class CancelToken:
    """A cancellation flag. A child token is cancelled when its parent is."""

    def __init__(self, parent: CancelToken | None = None) -> None:
        self._event = threading.Event()
        self._parent = parent
        self._reason: str | None = None

    def cancel(self, reason: str = "cancelled") -> None:
        if not self._event.is_set():
            self._reason = reason
            self._event.set()

    def is_set(self) -> bool:
        return self._event.is_set() or (self._parent is not None and self._parent.is_set())

    @property
    def reason(self) -> str | None:
        if self._reason is not None:
            return self._reason
        return self._parent.reason if self._parent is not None else None

    def wait(self, timeout: float) -> bool:
        """Sleep up to ``timeout`` seconds; return True as soon as cancelled."""
        end = time.monotonic() + timeout
        while True:
            if self.is_set():
                return True
            remaining = end - time.monotonic()
            if remaining <= 0:
                return False
            self._event.wait(min(remaining, 0.02))

    def child(self) -> CancelToken:
        return CancelToken(self)
