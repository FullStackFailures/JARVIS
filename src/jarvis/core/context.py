"""Context manager: conversation turns, entity table, recency pointers, context packets."""

from __future__ import annotations

import threading
from collections import deque
from pathlib import Path
from typing import Any

from pydantic import BaseModel, ConfigDict, Field

from jarvis.core.models import Entity, EntityHint, PermissionMode, Task, ToolResult
from jarvis.osal.types import CapabilityInventory


class Turn(BaseModel):
    model_config = ConfigDict(extra="forbid")
    role: str
    text: str
    task_id: str | None = None


class ContextPacket(BaseModel):
    model_config = ConfigDict(extra="forbid")
    conversation: list[Turn]
    active_task: dict[str, Any] | None
    environment: dict[str, Any]
    capabilities: dict[str, str]
    recent_results: list[dict[str, Any]]
    entities: list[Entity]
    pointers: dict[str, str] = Field(default_factory=dict)


class ContextManager:
    def __init__(self, inventory: CapabilityInventory, cwd: Path, mode: PermissionMode,
                 max_turns: int = 20, max_results: int = 10) -> None:
        self.inventory = inventory
        self.cwd = cwd
        self.mode = mode
        self._turns: deque[Turn] = deque(maxlen=max_turns)
        self._results: deque[dict[str, Any]] = deque(maxlen=max_results)
        self._entities: dict[str, Entity] = {}
        self._pointers: dict[str, str] = {}  # type -> latest entity id
        self._lock = threading.Lock()

    # ------------------------------------------------------------------ writes
    def add_turn(self, role: str, text: str, task_id: str | None = None) -> None:
        with self._lock:
            self._turns.append(Turn(role=role, text=text, task_id=task_id))

    def record_result(self, result: ToolResult, summary: str) -> None:
        with self._lock:
            self._results.append({"tool": result.tool, "ok": result.ok, "verified": result.verified,
                                  "summary": summary, "step_id": result.step_id})

    def register(self, hints: list[EntityHint], task_id: str, step_id: str) -> list[Entity]:
        out: list[Entity] = []
        with self._lock:
            for h in hints:
                ent = Entity(type=h.type, value=h.value, label=h.label,
                             source_step=step_id, source_task=task_id)
                self._entities[ent.id] = ent
                self._pointers[ent.type] = ent.id
                out.append(ent)
        return out

    # ------------------------------------------------------------------ reads
    def latest(self, entity_type: str) -> Entity | None:
        with self._lock:
            eid = self._pointers.get(entity_type)
            return self._entities.get(eid) if eid else None

    def resolve_ordinal(self, entity_type: str, ordinal: int) -> tuple[Any | None, str | None]:
        """Return (item, problem). ``ordinal`` is 1-based; -1 means the last item."""
        ent = self.latest(entity_type)
        if ent is None:
            return None, f"there is no earlier {entity_type.replace('_', ' ')} to refer to"
        if ent.is_stale():
            return None, f"the earlier {entity_type.replace('_', ' ')} is out of date"
        items = ent.value if isinstance(ent.value, list) else []
        if not items:
            return None, f"the earlier {entity_type.replace('_', ' ')} was empty"
        idx = ordinal - 1 if ordinal > 0 else len(items) + ordinal
        if idx < 0 or idx >= len(items):
            return None, f"the earlier list has only {len(items)} item(s)"
        return items[idx], None

    def packet(self, task: Task | None = None) -> ContextPacket:
        inv = self.inventory
        with self._lock:
            turns = list(self._turns)[-6:]
            results = list(self._results)[-5:]
            entities = [e for e in self._entities.values() if not e.is_stale()][-10:]
            pointers = dict(self._pointers)
        return ContextPacket(
            conversation=turns,
            active_task={"id": task.id, "goal": task.goal, "status": task.status.value} if task else None,
            environment={
                "os": inv.os.system, "os_version": inv.os.release, "arch": inv.os.arch,
                "cwd": str(self.cwd), "shell": inv.shell.default_shell,
                "session": inv.session.session_type, "graphical": inv.session.graphical,
                "elevated": inv.privilege.is_elevated, "permission_mode": self.mode.value,
            },
            capabilities={k: v.status.value for k, v in inv.capabilities.items()},
            recent_results=results,
            entities=entities,
            pointers=pointers,
        )
