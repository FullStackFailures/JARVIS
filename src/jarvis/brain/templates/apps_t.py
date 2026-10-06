"""Application goal family: list installed applications, open an application or a kind of application."""

from __future__ import annotations

import re

from jarvis.brain.lexicon import Match, Query, ordinal_of
from jarvis.brain.templates.base import Built, GoalTemplate, RouteContext
from jarvis.core.models import ExecMode, Plan, Postcondition, RequestClass, Step

_OPEN_RE = re.compile(r"^(?:please\s+)?(?:can you\s+|could you\s+)?(?:open|launch|start)\b\s*(?P<target>.*)$", re.I)
_KIND_WORDS: list[tuple[str, tuple[str, ...]]] = [
    ("browser", ("browser", "web browser", "internet browser", "internet", "web")),
    ("terminal", ("terminal", "terminal emulator", "console", "command line", "command prompt", "shell")),
    ("editor", ("editor", "text editor", "code editor", "ide")),
    ("file_manager", ("file manager", "file browser", "file explorer")),
    ("media", ("media player", "music player", "video player")),
]
_FILLER = re.compile(r"^(?:(?:my|the|a|an|some|default|up|me)\s+)+", re.I)
_REFERENCE = {"it", "that", "this", "that one", "this one"}


def _clean_target(t: str) -> str:
    t = re.sub(r"[.!?]+$", "", t.strip())
    t = _FILLER.sub("", t)
    t = re.sub(r"\s+(?:app|application|program|please)$", "", t, flags=re.I)
    return t.strip()


class AppsTemplate(GoalTemplate):
    name = "applications"
    request_class = RequestClass.APPLICATION

    def match(self, q: Query, rc: RouteContext) -> Match | None:
        m = _OPEN_RE.match(q.raw)
        if m:
            return Match(0.9, {"intent": "open", "target": _clean_target(m.group("target"))})
        if q.has("applications", "apps", "programs", "software", "browsers", "terminals", "editors") and q.has(
            "installed", "list", "show", "what", "which", "available", "have"
        ):
            kind = None
            for k, words in _KIND_WORDS:
                if q.has(*(w + "s" for w in words if not w.endswith("s")), *words):
                    kind = k
                    break
            return Match(0.8, {"intent": "list", "kind": kind})
        if q.has("browsers", "browser") and q.has("installed", "available", "which", "what"):
            return Match(0.8, {"intent": "list", "kind": "browser"})
        return None

    def build(self, q: Query, m: Match, rc: RouteContext) -> Built:
        if m.slots["intent"] == "list":
            args: dict[str, object] = {}
            if m.slots.get("kind"):
                args["kind"] = m.slots["kind"]
            step = Step(id="s1", tool="apps.discover", arguments=args, description="list installed applications")
            return Built(plan=Plan(goal=q.raw, steps=[step], created_by="template:applications"))

        target = str(m.slots["target"])
        if not target:
            return Built(clarification="What would you like me to open? For example: \"open my browser\" "
                                        "or \"open <application name>\".")
        low = target.lower()

        # contextual references: "open it", "open the first one"
        ordn = ordinal_of(low)
        if low in _REFERENCE or ordn is not None:
            if low in _REFERENCE or low.endswith(("one", "result", "app", "application")) or ordn is not None:
                if ordn is not None:
                    item, problem = rc.ctx.resolve_ordinal("app_list", ordn)
                else:
                    ent = rc.ctx.latest("app")
                    item, problem = (ent.value, None) if ent and not ent.is_stale() else (
                        None, "there is no recently mentioned application")
                if problem or not isinstance(item, dict):
                    return Built(clarification=f"I can't tell which application you mean: {problem}. "
                                               "Tell me its name or list the installed applications first.")
                step = Step(id="s1", tool="apps.open", arguments={"app_id": item["id"]}, mode=ExecMode.FOREGROUND,
                            description=f"open {item.get('name', item['id'])}")
                return Built(plan=Plan(goal=q.raw, steps=[step], created_by="template:applications"))

        kind = None
        for k, words in _KIND_WORDS:
            if low in words:
                kind = k
                break
        args = {"kind": kind} if kind else {"query": target}
        discover = Step(
            id="s1", tool="apps.discover", arguments=args,
            postcondition=Postcondition(kind="truthy", path="data.preferred_id",
                                        description="exactly one suitable application was identified"),
            description=f"find {'a ' + kind if kind else repr(target)}",
        )
        open_step = Step(
            id="s2", tool="apps.open", arguments={"app_id": "${s1.data.preferred_id}"},
            depends_on=["s1"], mode=ExecMode.FOREGROUND, description="open it",
            meta={"fallback_same_kind": bool(kind), "kind": kind, "target": target},
        )
        return Built(plan=Plan(goal=q.raw, steps=[discover, open_step], created_by="template:applications"))
