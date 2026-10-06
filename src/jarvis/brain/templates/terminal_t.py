"""Terminal goal family: run ONE explicitly given command as an argv (never a shell string)."""

from __future__ import annotations

import re
import shlex

from jarvis.brain.lexicon import Match, Query
from jarvis.brain.templates.base import Built, GoalTemplate, RouteContext
from jarvis.core.models import Plan, RequestClass, Step
from jarvis.policy.commands import READONLY_COMMANDS, looks_like_shell_pipeline

_VERB = re.compile(r"\b(?:run|execute|exec)\b", re.I)
_BACKTICK = re.compile(r"`([^`]+)`")
_AFTER_COLON = re.compile(r"(?:command|terminal|shell|cmd|cli)\s*[:\-]\s*(?P<c>.+)$", re.I)
_RUN_X = re.compile(r"^(?:please\s+)?(?:run|execute)\s+(?P<c>[^\s].*)$", re.I)


class TerminalTemplate(GoalTemplate):
    name = "terminal_command"
    request_class = RequestClass.TERMINAL

    def match(self, q: Query, rc: RouteContext) -> Match | None:
        if not _VERB.search(q.raw):
            return None
        m = _BACKTICK.search(q.raw)
        if m:
            return Match(0.95, {"command": m.group(1).strip()})
        m = _AFTER_COLON.search(q.raw)
        if m:
            return Match(0.95, {"command": m.group("c").strip().strip("\"'")})
        if q.has("command", "terminal", "shell"):
            return Match(0.7, {"command": None})
        m = _RUN_X.match(q.raw)
        if m:
            return Match(0.65, {"command": m.group("c").strip().strip("\"'"), "bare": True})
        return None

    def build(self, q: Query, m: Match, rc: RouteContext) -> Built:
        command = m.slots.get("command")
        if not command:
            return Built(clarification="Which command should I run? Give it like: run command: `hostname`")
        if looks_like_shell_pipeline(str(command)):
            return Built(clarification=(
                "I only run a single program with plain arguments - no pipes, redirects, chaining or "
                "substitutions. Give me one command, or ask for the information directly "
                "(for example: \"get my IP\")."))
        try:
            argv = shlex.split(str(command), posix=(rc.osal.name != "windows"))
        except ValueError as exc:
            return Built(clarification=f"I couldn't parse that command ({exc}). Check the quoting and try again.")
        if not argv:
            return Built(clarification="The command was empty. Which command should I run?")
        if m.slots.get("bare") and argv[0].lower() not in READONLY_COMMANDS and rc.osal.resolve_system_executable(argv[0]) is None:
            return Built(clarification=(
                f"Do you want me to run {argv[0]!r} as a terminal command, or open it as an application? "
                f"Say \"run command: `{command}`\" or \"open {argv[0]}\"."))
        step = Step(id="s1", tool="terminal.execute", arguments={"argv": argv}, description=f"run {argv[0]}")
        return Built(plan=Plan(goal=q.raw, steps=[step], created_by="template:terminal_command"))
