"""Named exclusive resource locks with ordered acquisition (deadlock-free) and timeouts."""

from __future__ import annotations

import threading
import time
from collections.abc import Iterable

from jarvis.common.cancel import CancelToken


class ResourceBusy(Exception):
    def __init__(self, resource: str) -> None:
        super().__init__(f"resource {resource!r} is busy")
        self.resource = resource


class ResourceLocks:
    def __init__(self) -> None:
        self._locks: dict[str, threading.Lock] = {}
        self._guard = threading.Lock()

    def _lock_for(self, name: str) -> threading.Lock:
        with self._guard:
            return self._locks.setdefault(name, threading.Lock())

    def acquire(self, resources: Iterable[str], timeout_s: float, cancel: CancelToken | None = None) -> list[str]:
        """Acquire all resources in sorted order; release everything on failure."""
        held: list[str] = []
        deadline = time.monotonic() + timeout_s
        try:
            for name in sorted(set(resources)):
                lock = self._lock_for(name)
                while True:
                    remaining = deadline - time.monotonic()
                    if remaining <= 0:
                        raise ResourceBusy(name)
                    if cancel is not None and cancel.is_set():
                        raise ResourceBusy(name)
                    if lock.acquire(timeout=min(remaining, 0.05)):
                        held.append(name)
                        break
        except BaseException:
            self.release(held)
            raise
        return held

    def release(self, held: Iterable[str]) -> None:
        for name in held:
            self._lock_for(name).release()

    def is_held(self, name: str) -> bool:
        lock = self._lock_for(name)
        if lock.acquire(blocking=False):
            lock.release()
            return False
        return True
