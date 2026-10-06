"""The Native Brain's presence in the model gateway.

It is deliberately honest: it is NOT a text generator. The deterministic control plane
(router, templates, policy, verification, recovery) does its work outside the gateway; this
adapter exists so the gateway can report the native backend's health and capabilities
uniformly and so a request that needs generation is refused with a structured error.
"""

from __future__ import annotations

from jarvis.core.models import (
    HealthReport,
    ModelCapabilities,
    ModelError,
    ModelErrorClass,
    ModelRequest,
    ModelResponse,
)
from jarvis.models.base import Reasoner


class NativeLiteReasoner(Reasoner):
    backend_id = "native"
    local = True

    def capabilities(self) -> ModelCapabilities:
        return ModelCapabilities(
            backend_id="native",
            model="deterministic-control-plane",
            supports_json_schema=False,
            supports_streaming=False,
            supports_open_planning=False,
            local=True,
            notes=[
                "handles known goal families via templates (system facts, files, applications, one terminal command)",
                "cannot plan novel multi-step goals or hold open-ended conversation",
            ],
        )

    def health(self, deep: bool = False) -> HealthReport:
        return HealthReport(backend_id="native", server_reachable=True, model_present=True,
                            generation_ok=True, detail="in-process deterministic control plane")

    def complete(self, request: ModelRequest) -> ModelResponse:
        return ModelResponse(
            request_id=request.request_id, backend_id="native", ok=False,
            error=ModelError(cls=ModelErrorClass.CAPABILITY_UNSUPPORTED, backend_id="native",
                             message="the native brain does not generate free text"),
        )
