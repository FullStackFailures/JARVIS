"""Ollama backend (local). Talks to the documented REST API: /api/tags and /api/chat."""

from __future__ import annotations

import time
from collections.abc import Iterator
from typing import Any

from jarvis.config.schema import OllamaConfig
from jarvis.core.models import (
    HealthReport,
    ModelCapabilities,
    ModelError,
    ModelErrorClass,
    ModelRequest,
    ModelResponse,
)
from jarvis.models.base import Reasoner
from jarvis.models.http import HttpFailure, request_json, stream_ndjson


def model_matches(wanted: str, installed: list[str]) -> bool:
    if wanted in installed:
        return True
    if ":" not in wanted:
        return f"{wanted}:latest" in installed
    return False


class OllamaReasoner(Reasoner):
    backend_id = "ollama"
    local = True

    def __init__(self, cfg: OllamaConfig) -> None:
        self.cfg = cfg
        self._base = cfg.base_url.rstrip("/")

    def capabilities(self) -> ModelCapabilities:
        return ModelCapabilities(
            backend_id=self.backend_id,
            model=self.cfg.model,
            supports_json_schema=True,
            supports_streaming=True,
            supports_open_planning=True,
            local=True,
            notes=["planning quality depends entirely on the selected model"],
        )

    def health(self, deep: bool = False) -> HealthReport:
        if not self.cfg.enabled:
            return HealthReport(backend_id=self.backend_id, configured=False,
                                detail="local AI is not enabled in configuration")
        try:
            tags = request_json("GET", f"{self._base}/api/tags", backend_id=self.backend_id,
                                timeout=self.cfg.health_timeout_s, use_env_proxy=False)
        except HttpFailure as f:
            return HealthReport(backend_id=self.backend_id, server_reachable=False,
                                detail=f"{f.error.cls.value}: {f.error.message}")
        installed = [m.get("name", "") for m in tags.get("models", []) if isinstance(m, dict)]
        if not self.cfg.model:
            return HealthReport(backend_id=self.backend_id, server_reachable=True, model_present=None,
                                detail=f"no model selected; installed: {', '.join(installed) or 'none'}")
        present = model_matches(self.cfg.model, installed)
        report = HealthReport(
            backend_id=self.backend_id, server_reachable=True, model_present=present,
            detail="" if present else f"model {self.cfg.model!r} is not installed "
                                       f"(installed: {', '.join(installed) or 'none'})",
        )
        if deep and present:
            probe = self.complete(ModelRequest(
                purpose="health", messages=[{"role": "user", "content": "Reply with the word ok."}],
                max_tokens=8, timeout_s=self.cfg.timeout_s))
            report.generation_ok = probe.ok
            if not probe.ok and probe.error:
                report.detail = f"{probe.error.cls.value}: {probe.error.message}"
        return report

    def _body(self, request: ModelRequest, stream: bool) -> dict[str, Any]:
        body: dict[str, Any] = {
            "model": self.cfg.model,
            "messages": request.messages,
            "stream": stream,
            "options": {"temperature": request.temperature, "num_predict": request.max_tokens},
        }
        if request.response_schema is not None:
            body["format"] = request.response_schema
        return body

    def complete(self, request: ModelRequest) -> ModelResponse:
        started = time.monotonic()
        if not self.cfg.model:
            return self._fail(request, ModelErrorClass.NOT_CONFIGURED, "no Ollama model selected", started)
        try:
            raw = request_json("POST", f"{self._base}/api/chat", backend_id=self.backend_id,
                               body=self._body(request, False), timeout=request.timeout_s,
                               use_env_proxy=False)
        except HttpFailure as f:
            return ModelResponse(request_id=request.request_id, backend_id=self.backend_id,
                                 model=self.cfg.model, ok=False, error=f.error,
                                 latency_ms=int((time.monotonic() - started) * 1000))
        try:
            content = str(raw["message"]["content"])
        except (KeyError, TypeError):
            return self._fail(request, ModelErrorClass.BAD_RESPONSE, "missing message.content", started)
        usage = {"input_tokens": int(raw.get("prompt_eval_count") or 0),
                 "output_tokens": int(raw.get("eval_count") or 0)}
        return ModelResponse(
            request_id=request.request_id, backend_id=self.backend_id, model=self.cfg.model, ok=True,
            content=content, usage=usage, finish_reason=raw.get("done_reason"),
            latency_ms=int((time.monotonic() - started) * 1000),
        )

    def stream(self, request: ModelRequest) -> Iterator[str]:
        for chunk in stream_ndjson(f"{self._base}/api/chat", backend_id=self.backend_id,
                                   body=self._body(request, True), timeout=request.timeout_s,
                                   use_env_proxy=False):
            piece = chunk.get("message", {}).get("content")
            if piece:
                yield str(piece)
            if chunk.get("done"):
                return

    def _fail(self, request: ModelRequest, cls: ModelErrorClass, msg: str, started: float) -> ModelResponse:
        return ModelResponse(
            request_id=request.request_id, backend_id=self.backend_id, model=self.cfg.model, ok=False,
            error=ModelError(cls=cls, message=msg, backend_id=self.backend_id),
            latency_ms=int((time.monotonic() - started) * 1000),
        )


