"""Native Brain router: score goal templates, resolve compound requests, never guess.

Outcomes: a Plan, a conversational reply kind, a clarification question, an UNSUPPORTED
statement (known-but-deferred capability), or UNKNOWN (no template; a reasoner may plan).
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Any

from jarvis.brain.lexicon import Match, Query, split_clauses
from jarvis.brain.templates import GoalTemplate, RouteContext, default_templates
from jarvis.brain.templates.base import Built
from jarvis.core.models import Plan, RequestClass, Step

MIN_SCORE = 0.5


@dataclass
class Routed:
    kind: str  # plan | reply | clarify | unsupported | unknown
    request_class: RequestClass
    templates: list[str] = field(default_factory=list)
    confidence: float = 0.0
    plan: Plan | None = None
    reply_kind: str | None = None
    text: str | None = None
    notes: list[str] = field(default_factory=list)
    unhandled: list[tuple[str, str]] = field(default_factory=list)

    def summary(self) -> dict[str, Any]:
        return {"kind": self.kind, "class": self.request_class.value, "templates": self.templates,
                "confidence": round(self.confidence, 2)}


class Router:
    def __init__(self, templates: list[GoalTemplate] | None = None) -> None:
        self.templates = templates if templates is not None else default_templates()

    # ------------------------------------------------------------------ single clause
    def _best(self, q: Query, rc: RouteContext) -> tuple[GoalTemplate, Match] | None:
        best: tuple[GoalTemplate, Match] | None = None
        for t in self.templates:
            m = t.match(q, rc)
            if m and m.score >= MIN_SCORE - 0.06 and (best is None or m.score > best[1].score):
                best = (t, m)
        return best

    def _to_routed(self, t: GoalTemplate, m: Match, built: Built) -> Routed:
        if built.plan is not None:
            return Routed("plan", t.request_class, [t.name], m.score, plan=built.plan, notes=built.notes or [])
        if built.reply_kind is not None:
            return Routed("reply", t.request_class, [t.name], m.score, reply_kind=built.reply_kind)
        if built.clarification is not None:
            return Routed("clarify", t.request_class, [t.name], m.score, text=built.clarification)
        return Routed("unsupported", t.request_class, [t.name], m.score, text=built.unsupported)

    # ------------------------------------------------------------------ public
    def route(self, text: str, rc: RouteContext) -> Routed:
        q = Query(text)
        if not q.low:
            return Routed("clarify", RequestClass.UNKNOWN, text="I didn't catch anything. What would you like me to do?")

        whole = self._best(q, rc)
        multi = self._try_compound(q, rc, whole)
        if multi is not None:
            return multi
        if whole is None:
            return Routed("unknown", RequestClass.UNKNOWN)
        t, m = whole
        return self._to_routed(t, m, t.build(q, m, rc))

    # ------------------------------------------------------------------ compound requests
    def _try_compound(self, q: Query, rc: RouteContext, whole: tuple[GoalTemplate, Match] | None) -> Routed | None:
        if whole and whole[0].name in {"conversation", "terminal_command"} and whole[1].score >= 0.9:
            return None
        clauses = split_clauses(q.raw)
        if len(clauses) < 2:
            return None
        per: list[tuple[str, tuple[GoalTemplate, Match] | None]] = [
            (c, self._best(Query(c), rc)) for c in clauses
        ]
        actionable = [
            (c, tm) for c, tm in per
            if tm and tm[0].name not in {"conversation", "deferred_capability"} and tm[1].score >= MIN_SCORE
        ]
        deferred = [c for c, tm in per if tm and tm[0].name == "deferred_capability"]
        names = {tm[0].name for _, tm in actionable}
        multi_intent = len(names) >= 2
        partial = len(names) == 1 and bool(deferred)
        if not (multi_intent or partial):
            return None  # same-family fragments ("RAM, disk and network") are handled by the whole-text route
        plans: list[Plan] = []
        notes: list[str] = []
        unhandled: list[tuple[str, str]] = []
        used: list[str] = []
        score = 1.0
        for c, tm in per:
            if tm is None:
                if multi_intent:
                    unhandled.append((c, "I don't have a built-in way to do this"))
                continue
            t, m = tm
            built = t.build(Query(c), m, rc)
            if built.plan is None:
                reason = built.clarification or built.unsupported or "not actionable"
                if t.name == "deferred_capability" or multi_intent:
                    unhandled.append((c, reason))
                continue
            plans.append(built.plan)
            notes.extend(built.notes or [])
            used.append(t.name)
            score = min(score, m.score)
        if not plans:
            return None
        merged = merge_plans(q.raw, plans)
        return Routed("plan", RequestClass.UNKNOWN, sorted(set(used)), score, plan=merged, notes=notes,
                      unhandled=unhandled)


_REF = re.compile(r"\$\{s([0-9]+)\.")


def merge_plans(goal: str, plans: list[Plan]) -> Plan:
    """Concatenate independent plans, renumbering step ids, references and dependencies."""
    steps: list[Step] = []
    assumptions: list[str] = []
    offset = 0
    for p in plans:
        mapping = {s.id: f"s{offset + i + 1}" for i, s in enumerate(p.steps)}

        def fix(val: Any, mapping: dict[str, str] = mapping) -> Any:
            if isinstance(val, str):
                return _REF.sub(lambda m: "${" + mapping[f"s{m.group(1)}"] + ".", val)
            if isinstance(val, dict):
                return {k: fix(v) for k, v in val.items()}
            if isinstance(val, list):
                return [fix(v) for v in val]
            return val

        for s in p.steps:
            steps.append(s.model_copy(update={
                "id": mapping[s.id],
                "arguments": fix(s.arguments),
                "depends_on": [mapping[d] for d in s.depends_on],
            }))
        assumptions.extend(p.assumptions)
        offset += len(p.steps)
    return Plan(goal=goal, steps=steps, created_by="template:compound", assumptions=assumptions)
