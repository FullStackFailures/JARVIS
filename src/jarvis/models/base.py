"""Provider-neutral reasoning interface. Nothing outside models/ may import a provider module."""

from __future__ import annotations

from abc import ABC, abstractmethod
from collections.abc import Iterator

from jarvis.core.models import HealthReport, ModelCapabilities, ModelRequest, ModelResponse


class Reasoner(ABC):
    backend_id: str
    local: bool = True

    @abstractmethod
    def capabilities(self) -> ModelCapabilities: ...

    @abstractmethod
    def health(self, deep: bool = False) -> HealthReport:
        """Three-level health: server reachable, model present, generation OK (deep only).

        Must never raise.
        """

    @abstractmethod
    def complete(self, request: ModelRequest) -> ModelResponse:
        """Single non-streaming completion. Must never raise: failures are ``ok=False`` responses."""

    def stream(self, request: ModelRequest) -> Iterator[str]:
        raise NotImplementedError(f"{self.backend_id} does not support streaming")

    def cancel(self, request_id: str) -> None:  # best effort; default no-op
        return None
