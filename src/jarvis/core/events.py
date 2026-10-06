"""Minimal thread-safe in-process event bus (topic prefix subscription)."""

from __future__ import annotations

import logging
import threading
from collections.abc import Callable

from jarvis.core.models import Event

log = logging.getLogger(__name__)
Handler = Callable[[Event], None]


class EventBus:
    def __init__(self) -> None:
        self._subs: list[tuple[str, Handler]] = []
        self._lock = threading.Lock()

    def subscribe(self, topic_prefix: str, handler: Handler) -> None:
        with self._lock:
            self._subs.append((topic_prefix, handler))

    def unsubscribe(self, handler: Handler) -> None:
        with self._lock:
            self._subs = [(p, h) for p, h in self._subs if h is not handler]

    def publish(self, topic: str, **payload: object) -> Event:
        event = Event(topic=topic, payload=dict(payload))
        with self._lock:
            targets = [h for prefix, h in self._subs if topic.startswith(prefix)]
        for handler in targets:
            try:
                handler(event)
            except Exception:  # a bad subscriber must never break the publisher
                log.exception("event handler failed for %s", topic)
        return event
