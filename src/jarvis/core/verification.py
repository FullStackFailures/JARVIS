"""Postcondition evaluation over a ToolResult."""

from __future__ import annotations

from typing import Any

from jarvis.core.models import Postcondition, ToolResult

_MISSING = object()


def lookup(result: ToolResult, path: str) -> Any:
    """Resolve 'data.a.b' (or 'ok', 'verified', ...) against a result; _MISSING if absent."""
    parts = path.split(".")
    cur: Any = result.model_dump(mode="python")
    for p in parts:
        if isinstance(cur, dict) and p in cur:
            cur = cur[p]
        elif isinstance(cur, list) and p.isdigit() and int(p) < len(cur):
            cur = cur[int(p)]
        else:
            return _MISSING
    return cur


def evaluate(pc: Postcondition, result: ToolResult) -> tuple[bool | None, str]:
    """Return (verified, note). ``None`` means the condition defers to the tool's own verify()."""
    if pc.kind == "tool_verified":
        return None, "deferred to tool verification"
    value = lookup(result, pc.path)
    what = pc.description or f"{pc.kind} {pc.path}"
    if value is _MISSING:
        return False, f"postcondition not met: {pc.path} is absent ({what})"
    if pc.kind == "field_present":
        return True, f"{pc.path} present"
    if pc.kind == "truthy":
        ok = bool(value)
        return ok, f"{pc.path} is {'set' if ok else 'empty or null'}" + ("" if ok else f" ({what})")
    if pc.kind == "min_items":
        n = len(value) if hasattr(value, "__len__") else 0
        need = int(pc.value if pc.value is not None else 1)
        return n >= need, f"{pc.path} has {n} item(s), need at least {need}"
    if pc.kind == "equals":
        ok = value == pc.value
        return ok, f"{pc.path} == {pc.value!r}" if ok else f"{pc.path} is {value!r}, expected {pc.value!r}"
    return False, f"unknown postcondition kind {pc.kind!r}"
