"""Model gateway: backend selection, health, retry, schema enforcement, privacy-aware fallback.

``route`` never raises. A failure is a ``ModelResponse(ok=False)`` carrying a structured
``ModelError`` and the list of backends that were tried.
"""

from __future__ import annotations

import json
import random
import threading
import time
from collections.abc import Callable
from typing import Any

from jsonschema import Draft202012Validator

from jarvis.core.models import (
    HealthReport,
    ModelCapabilities,
    ModelError,
    ModelErrorClass,
    ModelRequest,
    ModelResponse,
)
from jarvis.models.base import Reasoner

DISPLAY_NAMES = {"native": "JARVIS Brain", "ollama": "Local AI", "remote": "External API"}


def _validate_json(content: str, schema: dict[str, Any]) -> tuple[Any, str | None]:
    try:
        parsed = json.loads(content)
    except json.JSONDecodeError as exc:
        return None, f"output is not valid JSON: {exc.msg}"
    errors = sorted(Draft202012Validator(schema).iter_errors(parsed), key=lambda e: list(e.path))
    if errors:
        e = errors[0]
        loc = ".".join(str(p) for p in e.path) or "(root)"
        return None, f"schema violation at {loc}: {e.message}"
    return parsed, None


class ModelGateway:
    def __init__(
        self,
        backends: dict[str, Reasoner],
        *,
        default: str = "native",
        fallback_order: list[str] | None = None,
        health_ttl_s: float = 60.0,
        max_retries: int = 2,
        retry_backoff_s: float = 0.5,
        sleep: Callable[[float], None] = time.sleep,
        jitter: bool = True,
    ) -> None:
        self.backends = backends
        self.default = default
        self.fallback_order = fallback_order or []
        self.health_ttl_s = health_ttl_s
        self.max_retries = max_retries
        self.retry_backoff_s = retry_backoff_s
        self._sleep = sleep
        self._jitter = jitter
        self._health: dict[str, HealthReport] = {}
        self._lock = threading.Lock()

    # ------------------------------------------------------------------ ordering / health
    def order(self) -> list[str]:
        seen: list[str] = []
        for b in [self.default, *self.fallback_order]:
            if b in self.backends and b not in seen:
                seen.append(b)
        return seen

    def health(self, backend_id: str, *, deep: bool = False, force: bool = False) -> HealthReport:
        with self._lock:
            cached = self._health.get(backend_id)
        fresh = cached is not None and (time.time() - cached.checked_at) < self.health_ttl_s
        if cached is not None and fresh and not force and (not deep or cached.generation_ok is not None):
            return cached
        report = self.backends[backend_id].health(deep=deep)
        with self._lock:
            self._health[backend_id] = report
        return report

    def invalidate(self, backend_id: str) -> None:
        with self._lock:
            self._health.pop(backend_id, None)

    def health_all(self, *, deep: bool = False) -> dict[str, HealthReport]:
        return {b: self.health(b, deep=deep, force=True) for b in self.backends}

    def capabilities(self, backend_id: str) -> ModelCapabilities:
        return self.backends[backend_id].capabilities()

    def active_backend(self) -> str:
        """First backend in order whose health is usable."""
        for b in self.order():
            if self.health(b).usable:
                return b
        return "native" if "native" in self.backends else ""

    def status_lines(self) -> list[str]:
        active = self.active_backend()
        lines = []
        for bid, report in self.health_all().items():
            name = DISPLAY_NAMES.get(bid, bid)
            caps = self.backends[bid].capabilities()
            label = f"{name}: "
            if bid == "native":
                label += "ACTIVE" if active == "native" else "AVAILABLE"
            else:
                model = f" {caps.model}" if caps.model else ""
                tag = "ACTIVE" if active == bid else report.level
                label += f"{model.strip()} - {tag}" if model else tag
                if report.detail and report.level not in {"AVAILABLE", "READY (generation untested)"}:
                    label += f" ({report.detail})"
            lines.append(label)
        return lines

    # ------------------------------------------------------------------ routing
    def route(
        self,
        request: ModelRequest,
        *,
        require_open_planning: bool = False,
        backends: list[str] | None = None,
    ) -> ModelResponse:
        tried: list[str] = []
        last_error: ModelError | None = None
        for bid in backends or self.order():
            reasoner = self.backends[bid]
            caps = reasoner.capabilities()
            if request.privacy_class == "local_only" and not reasoner.local:
                tried.append(f"{bid}:privacy_blocked")
                last_error = ModelError(cls=ModelErrorClass.PRIVACY_BLOCKED, backend_id=bid,
                                        message="request is local_only; external backend skipped")
                continue
            if require_open_planning and not caps.supports_open_planning:
                tried.append(f"{bid}:capability_unsupported")
                last_error = ModelError(cls=ModelErrorClass.CAPABILITY_UNSUPPORTED, backend_id=bid,
                                        message=f"{bid} cannot plan open-ended goals")
                continue
            if request.response_schema is not None and not caps.supports_json_schema:
                tried.append(f"{bid}:capability_unsupported")
                last_error = ModelError(cls=ModelErrorClass.CAPABILITY_UNSUPPORTED, backend_id=bid,
                                        message=f"{bid} cannot enforce JSON schemas")
                continue
            health = self.health(bid)
            if not health.usable:
                cls = (ModelErrorClass.NOT_CONFIGURED if not health.configured
                       else ModelErrorClass.SERVER_UNREACHABLE if health.server_reachable is False
                       else ModelErrorClass.MODEL_MISSING)
                tried.append(f"{bid}:{cls.value}")
                last_error = ModelError(cls=cls, backend_id=bid, message=health.detail or health.level)
                continue
            resp = self._attempt(reasoner, request)
            if resp.ok:
                resp.fallbacks_tried = tried
                return resp
            assert resp.error is not None
            tried.append(f"{bid}:{resp.error.cls.value}")
            last_error = resp.error
            self.invalidate(bid)
        return ModelResponse(
            request_id=request.request_id,
            backend_id="gateway",
            ok=False,
            error=ModelError(
                cls=ModelErrorClass.NO_BACKEND,
                message="no reasoning backend could serve this request"
                        + (f" (last: {last_error.cls.value}: {last_error.message})" if last_error else ""),
            ),
            fallbacks_tried=tried,
        )

    def _attempt(self, reasoner: Reasoner, request: ModelRequest) -> ModelResponse:
        req = request
        repaired = False
        attempt = 0
        while True:
            resp = reasoner.complete(req)
            if resp.ok:
                if req.response_schema is None:
                    return resp
                parsed, problem = _validate_json(resp.content, req.response_schema)
                if problem is None:
                    resp.parsed = parsed
                    return resp
                if not repaired:
                    repaired = True
                    req = req.model_copy(update={"messages": [
                        *req.messages,
                        {"role": "assistant", "content": resp.content},
                        {"role": "user", "content": f"Your reply was rejected: {problem}. "
                                                    "Reply again with only JSON matching the schema."},
                    ]})
                    continue
                return ModelResponse(
                    request_id=request.request_id, backend_id=resp.backend_id, model=resp.model, ok=False,
                    content=resp.content, latency_ms=resp.latency_ms,
                    error=ModelError(cls=ModelErrorClass.SCHEMA_INVALID, message=problem,
                                     backend_id=resp.backend_id))
            assert resp.error is not None
            if resp.error.retryable and attempt < self.max_retries:
                delay = self.retry_backoff_s * (2 ** attempt)
                if self._jitter:
                    delay *= 0.5 + random.random()
                self._sleep(delay)
                attempt += 1
                continue
            return resp
