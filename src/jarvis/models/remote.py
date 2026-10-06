"""External-provider adapter (OpenAI-compatible chat completions).

This is the reference implementation of the external-provider interface. Other providers
are added as further ``Reasoner`` subclasses; nothing outside models/ changes.
The API key is fetched lazily through a callable and is never stored on the instance.
"""

from __future__ import annotations

import time
from collections.abc import Callable
from typing import Any

from jarvis.config.schema import RemoteConfig
from jarvis.core.models import (
    HealthReport,
    ModelCapabilities,
    ModelError,
    ModelErrorClass,
    ModelRequest,
    ModelResponse,
)
from jarvis.models.base import Reasoner
from jarvis.models.http import HttpFailure, request_json


class OpenAICompatReasoner(Reasoner):
    backend_id = "remote"
    local = False

    def __init__(self, cfg: RemoteConfig, api_key: Callable[[], str | None]) -> None:
        self.cfg = cfg
        self._api_key = api_key
        self._base = cfg.base_url.rstrip("/")

    def capabilities(self) -> ModelCapabilities:
        return ModelCapabilities(
            backend_id=self.backend_id,
            model=self.cfg.model,
            supports_json_schema=True,
            supports_streaming=False,
            supports_open_planning=True,
            local=False,
            notes=["requests leave this machine; only privacy_class=may_leave_machine is routed here"],
        )

    def _headers(self) -> dict[str, str] | None:
        key = self._api_key()
        return {"Authorization": f"Bearer {key}"} if key else None

    def health(self, deep: bool = False) -> HealthReport:
        if not self.cfg.enabled:
            return HealthReport(backend_id=self.backend_id, configured=False,
                                detail="external API is not enabled in configuration")
        headers = self._headers()
        if headers is None:
            return HealthReport(backend_id=self.backend_id, configured=False,
                                detail=f"API key {self.cfg.api_key_name!r} is not set")
        try:
            listing = request_json("GET", f"{self._base}/models", backend_id=self.backend_id,
                                   headers=headers, timeout=self.cfg.health_timeout_s, use_env_proxy=True)
        except HttpFailure as f:
            reachable = f.error.cls == ModelErrorClass.AUTH
            return HealthReport(backend_id=self.backend_id, server_reachable=reachable or False,
                                detail=f"{f.error.cls.value}: {f.error.message}")
        ids = [m.get("id", "") for m in listing.get("data", []) if isinstance(m, dict)]
        present: bool | None = None
        if self.cfg.model and ids:
            present = self.cfg.model in ids
        report = HealthReport(backend_id=self.backend_id, server_reachable=True, model_present=present,
                              detail="" if present is not False else f"model {self.cfg.model!r} not listed")
        if deep and present is not False and self.cfg.model:
            probe = self.complete(ModelRequest(
                purpose="health", messages=[{"role": "user", "content": "Reply with the word ok."}],
                max_tokens=8, timeout_s=self.cfg.timeout_s, privacy_class="may_leave_machine"))
            report.generation_ok = probe.ok
            if not probe.ok and probe.error:
                report.detail = f"{probe.error.cls.value}: {probe.error.message}"
        return report

    def complete(self, request: ModelRequest) -> ModelResponse:
        started = time.monotonic()

        def fail(cls: ModelErrorClass, msg: str) -> ModelResponse:
            return ModelResponse(
                request_id=request.request_id, backend_id=self.backend_id, model=self.cfg.model, ok=False,
                error=ModelError(cls=cls, message=msg, backend_id=self.backend_id),
                latency_ms=int((time.monotonic() - started) * 1000))

        headers = self._headers()
        if headers is None:
            return fail(ModelErrorClass.NOT_CONFIGURED, f"API key {self.cfg.api_key_name!r} is not set")
        if not self.cfg.model:
            return fail(ModelErrorClass.NOT_CONFIGURED, "no external model selected")
        body: dict[str, Any] = {
            "model": self.cfg.model,
            "messages": request.messages,
            "temperature": request.temperature,
            "max_tokens": request.max_tokens,
        }
        if request.response_schema is not None:
            body["response_format"] = {
                "type": "json_schema",
                "json_schema": {"name": "jarvis_response", "schema": request.response_schema, "strict": False},
            }
        try:
            raw = request_json("POST", f"{self._base}/chat/completions", backend_id=self.backend_id,
                               body=body, headers=headers, timeout=request.timeout_s, use_env_proxy=True)
        except HttpFailure as f:
            return ModelResponse(request_id=request.request_id, backend_id=self.backend_id,
                                 model=self.cfg.model, ok=False, error=f.error,
                                 latency_ms=int((time.monotonic() - started) * 1000))
        try:
            choice = raw["choices"][0]
            content = str(choice["message"]["content"])
        except (KeyError, IndexError, TypeError):
            return fail(ModelErrorClass.BAD_RESPONSE, "missing choices[0].message.content")
        usage = raw.get("usage") or {}
        return ModelResponse(
            request_id=request.request_id, backend_id=self.backend_id, model=self.cfg.model, ok=True,
            content=content,
            usage={"input_tokens": int(usage.get("prompt_tokens") or 0),
                   "output_tokens": int(usage.get("completion_tokens") or 0)},
            finish_reason=choice.get("finish_reason"),
            latency_ms=int((time.monotonic() - started) * 1000),
        )
