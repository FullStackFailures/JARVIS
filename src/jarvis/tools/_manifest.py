"""Small helper that keeps tool manifests short and uniform."""

from __future__ import annotations

from collections.abc import Sequence
from typing import Any

from jarvis.core.models import (
    ExecMode,
    Postcondition,
    RiskLevel,
    SideEffect,
    Taint,
    ToolManifest,
)


def obj(props: dict[str, Any], required: Sequence[str] = (), extra: bool = False) -> dict[str, Any]:
    return {
        "type": "object",
        "properties": props,
        "required": list(required),
        "additionalProperties": extra,
    }


def build_manifest(
    name: str,
    description: str,
    input_schema: dict[str, Any],
    output_schema: dict[str, Any],
    *,
    risk: RiskLevel = RiskLevel.LOW,
    permissions: Sequence[str],
    side_effects: Sequence[SideEffect] = (SideEffect.NONE,),
    idempotent: bool = True,
    timeout_ms: int = 10_000,
    cancellable: bool = False,
    platforms: Sequence[str] = ("linux", "windows"),
    requires_capability: Sequence[str] = (),
    methods: Sequence[str] = (),
    resources: Sequence[str] = (),
    postcondition: Postcondition | None = None,
    taint: Taint = Taint.TRUSTED,
    modes: Sequence[ExecMode] = (ExecMode.BACKGROUND,),
    tags: Sequence[str] = (),
    examples: Sequence[dict[str, Any]] = (),
) -> ToolManifest:
    return ToolManifest(
        name=name,
        description=description,
        tags=list(tags),
        input_schema=input_schema,
        output_schema=output_schema,
        platforms=list(platforms),  # type: ignore[arg-type]
        requires_capability=list(requires_capability),
        methods=list(methods),
        risk=risk,
        permissions=list(permissions),
        side_effects=list(side_effects),
        idempotent=idempotent,
        timeout_ms=timeout_ms,
        cancellable=cancellable,
        execution_modes=list(modes),
        resources=list(resources),
        postcondition=postcondition,
        result_taint=taint,
        examples=list(examples),
    )
