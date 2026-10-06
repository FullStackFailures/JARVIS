"""Tool contract: a manifest plus an execute() implementation that only talks to the OSAL."""

from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, ClassVar

from jarvis.common.cancel import CancelToken
from jarvis.config.schema import JarvisConfig
from jarvis.core.models import (
    EntityHint,
    FailureClass,
    Postcondition,
    Taint,
    ToolManifest,
)
from jarvis.osal.base import OSAdapter
from jarvis.osal.types import CapabilityInventory, OsalError


class ToolFailure(Exception):
    """Raised by a tool to report a structured, expected failure."""

    def __init__(
        self,
        cls: FailureClass,
        message: str,
        *,
        retryable: bool = False,
        data: dict[str, Any] | None = None,
    ) -> None:
        super().__init__(message)
        self.cls = cls
        self.message = message
        self.retryable = retryable
        self.data = data or {}


_OSAL_TO_FAILURE = {
    "not_found": FailureClass.NOT_FOUND,
    "permission": FailureClass.PERMISSION,
    "unavailable": FailureClass.UNAVAILABLE,
    "invalid": FailureClass.INVALID_ARGUMENTS,
    "failed": FailureClass.TOOL_ERROR,
}


def failure_from_osal(exc: OsalError) -> ToolFailure:
    return ToolFailure(_OSAL_TO_FAILURE.get(exc.kind, FailureClass.TOOL_ERROR), exc.message)


@dataclass
class ToolContext:
    osal: OSAdapter
    config: JarvisConfig
    inventory: CapabilityInventory
    cancel: CancelToken
    cwd: Path
    task_id: str | None = None
    step_id: str | None = None
    env: dict[str, str] = field(default_factory=dict)
    notes_dir: Path | None = None


@dataclass
class ToolOutput:
    data: dict[str, Any]
    method: str
    taint: Taint | None = None
    entities: list[EntityHint] = field(default_factory=list)


@dataclass
class Verification:
    verified: bool | None
    note: str = ""
    data_update: dict[str, Any] | None = None


class Tool(ABC):
    manifest: ClassVar[ToolManifest]

    @abstractmethod
    def execute(self, args: dict[str, Any], ctx: ToolContext) -> ToolOutput: ...

    def verify(self, args: dict[str, Any], output: ToolOutput, ctx: ToolContext) -> Verification | None:
        """Tool-specific verification (used by postconditions of kind ``tool_verified``)."""
        return None

    def effective_timeout_ms(self, args: dict[str, Any]) -> int:
        return self.manifest.timeout_ms


def field_present(path: str, description: str = "") -> Postcondition:
    return Postcondition(kind="field_present", path=path, description=description)
