"""Deterministic failure -> alternative-strategy table (the Native Brain's recovery hook)."""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass
from typing import Any

from jarvis.core.models import FailureClass, Step, ToolResult

NON_RECOVERABLE = {
    FailureClass.POLICY_DENIED, FailureClass.CANCELLED, FailureClass.INVALID_ARGUMENTS,
    FailureClass.DEPENDENCY_FAILED, FailureClass.UNKNOWN_TOOL, FailureClass.CONTRACT_VIOLATION,
}


@dataclass
class Recovery:
    step: Step
    note: str


class RecoveryEngine:
    """Returns the next strategy for a failed step, or None. Never retries the same call blindly."""

    def next_strategy(
        self, step: Step, result: ToolResult, results: Mapping[str, ToolResult], resolved_args: dict[str, Any]
    ) -> Recovery | None:
        fc = result.failure_class
        if fc is None or fc in NON_RECOVERABLE:
            return None
        if step.tool == "terminal.execute":
            return self._terminal(step, result, resolved_args)
        if step.tool == "apps.open":
            return self._apps_open(step, result, results, resolved_args)
        return None

    @staticmethod
    def _terminal(step: Step, result: ToolResult, args: dict[str, Any]) -> Recovery | None:
        alts: list[list[str]] = list(step.meta.get("alternatives", []))
        if not alts:
            return None
        nxt, rest = alts[0], alts[1:]
        new_args = {**args, "argv": nxt}
        failed = args.get("argv", [""])[0]
        return Recovery(
            step.model_copy(update={"arguments": new_args, "meta": {**step.meta, "alternatives": rest}}),
            f"{failed} failed ({result.error.message if result.error else 'error'}); trying {nxt[0]} instead",
        )

    @staticmethod
    def _apps_open(step: Step, result: ToolResult, results: Mapping[str, ToolResult],
                   args: dict[str, Any]) -> Recovery | None:
        if not step.meta.get("fallback_same_kind"):
            return None  # an explicitly named app is never silently replaced by a different one
        discover = next((r for r in results.values() if r.tool == "apps.discover" and r.ok), None)
        if discover is None:
            return None
        tried = set(step.meta.get("tried", [])) | {args.get("app_id")}
        candidates = [a for a in discover.data.get("apps", []) if a.get("id") not in tried]
        if not candidates:
            return None
        nxt = candidates[0]
        failed_name = result.data.get("name") or args.get("app_id")
        return Recovery(
            step.model_copy(update={
                "arguments": {"app_id": nxt["id"]},
                "meta": {**step.meta, "tried": sorted(str(x) for x in tried | {nxt["id"]} if x is not None)},
                "depends_on": [],
            }),
            f"{failed_name} could not be started ({result.error.message if result.error else 'error'}); "
            f"using {nxt['name']} instead",
        )
