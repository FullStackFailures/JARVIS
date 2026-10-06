"""Tool registry: registration, contract validation, plugin discovery, availability."""

from __future__ import annotations

import importlib
import importlib.metadata
import logging
from dataclasses import dataclass
from typing import Any

from jsonschema import Draft202012Validator
from jsonschema.exceptions import SchemaError

from jarvis.core.models import ToolManifest
from jarvis.osal.types import Availability, CapabilityInventory
from jarvis.tools import BUILTIN_MODULES
from jarvis.tools.base import Tool

log = logging.getLogger(__name__)

KNOWN_PERMISSIONS = frozenset(
    {
        "system.read", "fs.read", "fs.write", "net.read", "apps.read", "apps.launch",
        "proc.read", "proc.exec_readonly", "proc.exec", "priv.elevate", "notes.write",
    }
)
PLUGIN_ENTRY_POINT_GROUP = "jarvis.tools"


@dataclass(frozen=True)
class ContractViolation:
    tool: str
    problem: str

    def __str__(self) -> str:
        return f"{self.tool}: {self.problem}"


@dataclass(frozen=True)
class ToolAvailability:
    available: bool
    reason: str | None = None


def check_manifest(m: ToolManifest) -> list[str]:
    """Return a list of contract problems for one manifest (empty == valid)."""
    problems: list[str] = []
    for label, schema in (("input_schema", m.input_schema), ("output_schema", m.output_schema)):
        try:
            Draft202012Validator.check_schema(schema)
        except SchemaError as exc:
            problems.append(f"{label} is not a valid JSON Schema: {exc.message}")
        if schema.get("type") != "object":
            problems.append(f"{label} must describe an object")
    if m.input_schema.get("additionalProperties") is not False:
        problems.append("input_schema must set additionalProperties: false (reject unknown arguments)")
    unknown = set(m.permissions) - KNOWN_PERMISSIONS
    if unknown:
        problems.append(f"unknown permission tokens: {sorted(unknown)}")
    if m.postcondition is None:
        problems.append("a default postcondition is required (verification is mandatory)")
    elif m.postcondition.kind != "tool_verified" and not m.postcondition.path:
        problems.append("postcondition needs a path unless kind is tool_verified")
    risky_effects = {"fs_write", "net_egress", "ui_interaction", "system_state", "external_comm"}
    declared = {getattr(e, "value", e) for e in m.side_effects}
    if getattr(m.risk, "value", m.risk) == "LOW" and declared & risky_effects and not set(m.permissions) <= {"notes.write"}:
        problems.append("a LOW-risk tool must not have write/egress/UI side effects (only notes.write is exempt)")
    if m.cancellable is False and m.timeout_ms > 120_000:
        problems.append("non-cancellable tools must not have a timeout above 120s")
    return problems


class ToolRegistry:
    def __init__(self) -> None:
        self._tools: dict[str, Tool] = {}

    # ------------------------------------------------------------------ registration
    def register(self, tool: Tool | type[Tool]) -> Tool:
        inst = tool() if isinstance(tool, type) else tool
        name = inst.manifest.name
        if name in self._tools:
            raise ValueError(f"tool already registered: {name}")
        problems = check_manifest(inst.manifest)
        if problems:
            raise ValueError(f"invalid manifest for {name}: " + "; ".join(problems))
        self._tools[name] = inst
        return inst

    def load_builtin(self) -> None:
        for mod_name in BUILTIN_MODULES:
            mod = importlib.import_module(mod_name)
            for cls in mod.TOOLS:
                self.register(cls)

    def load_plugins(self) -> list[str]:
        """Discover third-party tools via the ``jarvis.tools`` entry-point group."""
        loaded: list[str] = []
        for ep in importlib.metadata.entry_points(group=PLUGIN_ENTRY_POINT_GROUP):
            try:
                obj: Any = ep.load()
                classes = obj if isinstance(obj, (list, tuple)) else [obj]
                for cls in classes:
                    self.register(cls)
                    loaded.append(ep.name)
            except Exception as exc:  # a broken plugin must not break the agent
                log.warning("plugin %s failed to load: %s", ep.name, exc)
        return loaded

    # ------------------------------------------------------------------ lookup
    def get(self, name: str) -> Tool | None:
        return self._tools.get(name)

    def names(self) -> list[str]:
        return sorted(self._tools)

    def all(self) -> list[Tool]:
        return [self._tools[n] for n in self.names()]

    def validate_all(self) -> list[ContractViolation]:
        out: list[ContractViolation] = []
        for name, tool in self._tools.items():
            out.extend(ContractViolation(name, p) for p in check_manifest(tool.manifest))
        return out

    # ------------------------------------------------------------------ availability
    def availability(
        self, name: str, platform: str, inventory: CapabilityInventory
    ) -> ToolAvailability:
        tool = self._tools.get(name)
        if tool is None:
            return ToolAvailability(False, f"unknown tool {name!r}")
        m = tool.manifest
        if platform not in m.platforms:
            return ToolAvailability(False, f"not supported on {platform}")
        for cap in m.requires_capability:
            if inventory.status_of(cap) == Availability.UNAVAILABLE:
                return ToolAvailability(False, f"capability {cap!r} unavailable: {inventory.reason_of(cap)}")
        return ToolAvailability(True)

    def query(self, intent: str, platform: str, granted_perms: set[str] | None = None, limit: int = 8) -> list[Tool]:
        """Keyword/tag capability index: rank tools whose name, tags or description match ``intent``.

        Candidates only: policy still decides whether anything runs. Tools unsupported on ``platform`` or needing
        a permission outside ``granted_perms`` (when given) are excluded.
        """
        import re

        words = {w for w in re.findall(r"[a-z0-9_.]+", intent.lower()) if len(w) > 2}
        scored: list[tuple[float, str, Tool]] = []
        for t in self._tools.values():
            m = t.manifest
            if platform not in m.platforms:
                continue
            if granted_perms is not None and not set(m.permissions) <= granted_perms:
                continue
            name_parts = set(re.split(r"[._]", m.name.lower()))
            tags = {x.lower() for x in m.tags}
            desc = set(re.findall(r"[a-z0-9_]+", m.description.lower()))
            score = sum(3.0 * (w in tags) + 2.0 * (w in name_parts or w in m.name.lower()) + 1.0 * (w in desc)
                        for w in words)
            if score > 0:
                scored.append((score, m.name, t))
        scored.sort(key=lambda x: (-x[0], x[1]))
        return [t for _, _, t in scored[:limit]]

    def summaries(self) -> list[dict[str, Any]]:
        """Compact descriptions for reasoner prompts and --tools."""
        return [
            {
                "name": t.manifest.name,
                "description": t.manifest.description,
                "input_schema": t.manifest.input_schema,
                "risk": t.manifest.risk.value,
            }
            for t in self.all()
        ]
