"""Plan validation and (optional) reasoner-backed planning for goals no template covers."""

from __future__ import annotations

import json
import re
from dataclasses import dataclass
from typing import Any

from jsonschema import Draft202012Validator

from jarvis.config.schema import JarvisConfig
from jarvis.core.context import ContextPacket
from jarvis.core.models import ModelRequest, Plan, Step
from jarvis.models.gateway import ModelGateway
from jarvis.osal.types import CapabilityInventory
from jarvis.registry.registry import ToolRegistry

_REF = re.compile(r"\$\{(s[0-9]+)\.[A-Za-z0-9_.]+\}")


def _refs_in(value: Any) -> set[str]:
    if isinstance(value, str):
        return set(_REF.findall(value))
    if isinstance(value, dict):
        return set().union(*[_refs_in(v) for v in value.values()]) if value else set()
    if isinstance(value, list):
        return set().union(*[_refs_in(v) for v in value]) if value else set()
    return set()


def _has_refs(value: Any) -> bool:
    return bool(_refs_in(value))


def add_implicit_dependencies(plan: Plan) -> Plan:
    steps = []
    for s in plan.steps:
        deps = sorted(set(s.depends_on) | _refs_in(s.arguments))
        steps.append(s.model_copy(update={"depends_on": deps}))
    return plan.model_copy(update={"steps": steps})


class Planner:
    def __init__(self, registry: ToolRegistry, gateway: ModelGateway, config: JarvisConfig,
                 platform: str, inventory: CapabilityInventory) -> None:
        self.registry = registry
        self.gateway = gateway
        self.config = config
        self.platform = platform
        self.inventory = inventory

    # ------------------------------------------------------------------ validation
    def validate(self, plan: Plan) -> list[str]:
        problems: list[str] = []
        ids = [s.id for s in plan.steps]
        if not plan.steps:
            return ["plan has no steps"]
        if len(plan.steps) > self.config.limits.max_steps:
            problems.append(f"plan has {len(plan.steps)} steps; the limit is {self.config.limits.max_steps}")
        if len(set(ids)) != len(ids):
            problems.append("duplicate step ids")
        known = set(ids)
        for s in plan.steps:
            tool = self.registry.get(s.tool)
            if tool is None:
                problems.append(f"{s.id}: unknown tool {s.tool!r}")
                continue
            avail = self.registry.availability(s.tool, self.platform, self.inventory)
            if not avail.available:
                problems.append(f"{s.id}: {s.tool} is unavailable ({avail.reason})")
            for d in s.depends_on:
                if d not in known:
                    problems.append(f"{s.id}: depends on unknown step {d}")
                if d == s.id:
                    problems.append(f"{s.id}: depends on itself")
            for r in _refs_in(s.arguments):
                if r not in known:
                    problems.append(f"{s.id}: references unknown step {r}")
            if not _has_refs(s.arguments):
                v = Draft202012Validator(tool.manifest.input_schema)
                for e in sorted(v.iter_errors(s.arguments), key=lambda e: list(map(str, e.path)))[:3]:
                    loc = ".".join(str(p) for p in e.path) or "(root)"
                    problems.append(f"{s.id}: invalid arguments - {loc}: {e.message}")
        if not problems and self._has_cycle(plan):
            problems.append("plan dependencies contain a cycle")
        return problems

    @staticmethod
    def _has_cycle(plan: Plan) -> bool:
        deps = {s.id: set(s.depends_on) for s in plan.steps}
        done: set[str] = set()
        while deps:
            ready = [i for i, d in deps.items() if d <= done]
            if not ready:
                return True
            for i in ready:
                done.add(i)
                deps.pop(i)
        return False

    # ------------------------------------------------------------------ reasoner planning
    def _schema(self) -> dict[str, Any]:
        return {
            "type": "object",
            "properties": {
                "kind": {"enum": ["plan", "reply", "clarify"]},
                "text": {"type": "string"},
                "steps": {
                    "type": "array",
                    "maxItems": self.config.limits.max_steps,
                    "items": {
                        "type": "object",
                        "properties": {
                            "id": {"type": "string", "pattern": "^s[0-9]+$"},
                            "tool": {"enum": self.registry.names()},
                            "arguments": {"type": "object"},
                            "depends_on": {"type": "array", "items": {"type": "string"}},
                            "description": {"type": "string"},
                        },
                        "required": ["id", "tool", "arguments"],
                    },
                },
            },
            "required": ["kind"],
        }

    def _system_prompt(self, packet: ContextPacket) -> str:
        tools = json.dumps(self.registry.summaries(), separators=(",", ":"))
        return (
            "You are the planning component of JARVIS, an AI computer assistant. Reply with ONLY a JSON object.\n"
            'Use {"kind":"plan","steps":[...]} to act, {"kind":"reply","text":...} to answer conversationally, '
            'or {"kind":"clarify","text":...} when the request is ambiguous.\n'
            "Rules: use ONLY the tools listed; arguments must satisfy the tool's input_schema; never invent "
            "tools or shell strings (terminal.execute takes an argv array); steps are ids s1,s2,...; a step may "
            'reference an earlier step output as the exact string "${s1.data.field}" and must list it in depends_on; '
            "do not claim anything succeeded - results are verified by the system.\n"
            f"Environment: {json.dumps(packet.environment)}\nTools: {tools}"
        )

    def plan_with_reasoner(self, goal: str, packet: ContextPacket, task_id: str) -> PlannerResult:
        privacy = "may_leave_machine" if self.config.models.remote.allow_task_content else "local_only"
        messages = [
            {"role": "system", "content": self._system_prompt(packet)},
            {"role": "user", "content": goal},
        ]
        last_problems: list[str] = []
        tried: list[str] = []
        for _attempt in range(2):
            req = ModelRequest(task_id=task_id, purpose="plan", messages=messages,
                               response_schema=self._schema(), max_tokens=1500, timeout_s=60.0,
                               privacy_class=privacy)  # type: ignore[arg-type]
            resp = self.gateway.route(req, require_open_planning=True)
            tried = resp.fallbacks_tried
            if not resp.ok:
                msg = resp.error.message if resp.error else "no backend"
                return PlannerResult(kind="failed", text=msg, tried=tried)
            data = resp.parsed
            if data["kind"] in {"reply", "clarify"}:
                return PlannerResult(kind=data["kind"], text=str(data.get("text", "")),
                                     backend=resp.backend_id, tried=tried)
            try:
                plan = Plan(
                    goal=goal,
                    steps=[Step(id=s["id"], tool=s["tool"], arguments=s.get("arguments", {}),
                                depends_on=s.get("depends_on", []), description=s.get("description", ""))
                           for s in data.get("steps", [])],
                    created_by=f"reasoner:{resp.backend_id}",
                )
                plan = add_implicit_dependencies(plan)
                last_problems = self.validate(plan)
            except Exception as exc:
                last_problems = [f"malformed plan: {type(exc).__name__}: {exc}"]
                plan = None  # type: ignore[assignment]
            if not last_problems:
                return PlannerResult(kind="plan", plan=plan, backend=resp.backend_id, tried=tried)
            messages = [*messages, {"role": "assistant", "content": resp.content},
                        {"role": "user", "content": "That plan was rejected: " + "; ".join(last_problems)
                         + ". Reply again with a corrected JSON object."}]
        return PlannerResult(kind="failed", text="the reasoning backend produced an invalid plan twice: "
                             + "; ".join(last_problems), tried=tried)


@dataclass
class PlannerResult:
    kind: str  # plan | reply | clarify | failed
    plan: Plan | None = None
    text: str = ""
    backend: str = ""
    tried: list[str] | None = None
