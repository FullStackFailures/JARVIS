"""System-facts goal family: hostname, ip, memory, disk, cpu/os. Multi-resource requests run in parallel."""

from __future__ import annotations

from jarvis.brain.lexicon import Match, Query
from jarvis.brain.templates.base import Built, GoalTemplate, RouteContext
from jarvis.core.models import ExecMode, Plan, Postcondition, RequestClass, Step

RESOURCES: dict[str, tuple[str, ...]] = {
    "hostname": ("hostname", "host name", "computer name", "machine name", "pc name"),
    "ip": ("ip", "ip address", "ip addr", "ipv4", "my address", "network address", "network",
           "network state", "connectivity"),
    "memory": ("ram", "memory", "mem"),
    "disk": ("disk", "disk space", "storage", "hard drive", "free space", "drive space", "hard disk"),
    "info": ("cpu", "processor", "uptime", "os", "operating system", "system info",
             "system information", "kernel", "os version", "architecture", "system", "machine"),
}
TERMINAL_MODIFIERS = (
    "using the terminal", "using terminal", "in the terminal", "from the terminal", "via terminal",
    "via the terminal", "with the terminal", "using the command line", "using the shell",
    "using powershell", "using cmd", "using bash", "on the command line", "with a command",
)
_ORDER = ["hostname", "ip", "memory", "disk", "info"]


class SystemFactsTemplate(GoalTemplate):
    name = "system_facts"
    request_class = RequestClass.SYSTEM

    def match(self, q: Query, rc: RouteContext) -> Match | None:
        found = [r for r in _ORDER if q.has(*RESOURCES[r])]
        # "machine"/"system" alone are too weak: require a stronger resource or a question frame.
        strong = [r for r in found if not (r == "info" and not q.has(
            "cpu", "processor", "uptime", "os", "operating system", "system info", "system information",
            "kernel", "os version", "architecture"))]
        if not strong:
            return None
        if q.has("open", "launch", "start", "files", "folder", "directory", "installed", "applications", "apps"):
            if not q.has("ram", "cpu", "memory", "disk", "hostname"):
                return None
        score = min(0.9, 0.6 + 0.1 * len(strong))
        return Match(score, {"resources": strong, "via_terminal": q.has(*TERMINAL_MODIFIERS)})

    def build(self, q: Query, m: Match, rc: RouteContext) -> Built:
        resources: list[str] = list(m.slots["resources"])  # type: ignore[call-overload,arg-type]
        via_terminal = bool(m.slots["via_terminal"])
        steps: list[Step] = []
        notes: list[str] = []

        def add(tool: str, args: dict[str, object] | None = None, **kw: object) -> None:
            steps.append(Step(id=f"s{len(steps) + 1}", tool=tool, arguments=dict(args or {}),
                              mode=ExecMode.BACKGROUND, **kw))  # type: ignore[arg-type]

        for r in resources:
            if r == "hostname":
                add("system.hostname")
            elif r == "ip":
                recipes = rc.osal.command_recipes().get("net.addresses", [])
                if via_terminal and recipes:
                    add(
                        "terminal.execute",
                        {"argv": recipes[0], "parse_as": "net.addresses"},
                        postcondition=Postcondition(kind="min_items", path="data.parsed.addresses",
                                                    description="at least one address parsed"),
                        meta={"alternatives": recipes[1:], "ip_via_terminal": True},
                        description="local addresses via the terminal",
                    )
                else:
                    if via_terminal:
                        notes.append("no terminal recipe exists for addresses on this platform; used the system API")
                    add("net.get_addresses")
            elif r == "memory":
                add("system.memory")
            elif r == "disk":
                add("system.disk")
            elif r == "info":
                add("system.info")
        plan = Plan(goal=q.raw, steps=steps, created_by="template:system_facts",
                    assumptions=notes)
        return Built(plan=plan, notes=notes)
