"""Goal families added to close the Milestone 1 tool set: services, ports, processes, file search/read,
notes and application status. Slot extraction is explicit and conservative; ambiguity => clarification."""

from __future__ import annotations

import re

from jarvis.brain.lexicon import Match, Query
from jarvis.brain.templates.base import Built, GoalTemplate, RouteContext
from jarvis.core.models import Plan, RequestClass, Step

_NAME = r"[\w.@-]+"
KNOWN_SERVICES = {"ssh", "sshd", "openssh", "docker", "nginx", "apache", "apache2", "httpd", "cron", "crond",
                  "mysql", "mysqld", "mariadb", "postgres", "postgresql", "redis", "networkmanager",
                  "bluetooth", "cups", "winrm", "rdp", "defender", "firewall"}
NOT_A_THING = {"my", "the", "it", "this", "that", "network", "internet", "connection", "wifi", "wi-fi", "there"}

_IS_RUNNING = re.compile(
    rf"(?:\bis\b|\bcheck(?:\s+(?:if|whether))?\b|\bsee\s+if\b|\bverify(?:\s+that)?\b|\btell\s+me\s+if\b)\s+"
    rf"(?:the\s+|my\s+)?(?P<n>{_NAME})(?:\s+(?:service|daemon|server|app|application))?\s+"
    rf"(?:is\s+)?(?:currently\s+)?(?:running|active|up|started|enabled|alive|open)\b", re.I)
_STATUS_OF = re.compile(
    rf"\b(?:status|state)\s+of\s+(?:the\s+|my\s+)?(?P<n>{_NAME})(?:\s+(?:service|daemon|server))?\s*[?.!]*$", re.I)
_SVC_STATUS = re.compile(rf"\b(?P<n>{_NAME})\s+(?:service|daemon)\s+(?:status|state)\b", re.I)


def _status_target(q: Query) -> tuple[str, bool] | None:
    """(name, explicit_service_word) for 'is X running' style questions."""
    for pat in (_IS_RUNNING, _STATUS_OF, _SVC_STATUS):
        m = pat.search(q.raw)
        if m:
            name = m.group("n").strip(".?!,").lower()
            if name in NOT_A_THING:
                return None
            return name, q.has("service", "daemon", "systemd", "systemctl")
    return None


class ServiceStatusTemplate(GoalTemplate):
    name = "service_status"
    request_class = RequestClass.SYSTEM

    def match(self, q: Query, rc: RouteContext) -> Match | None:
        t = _status_target(q)
        if t is None:
            return None
        name, explicit = t
        if explicit or name in KNOWN_SERVICES:
            return Match(0.9, {"name": name})
        return None

    def build(self, q: Query, m: Match, rc: RouteContext) -> Built:
        step = Step(id="s1", tool="system.service_status", arguments={"name": m.slots["name"]},
                    description=f"check service {m.slots['name']}")
        return Built(plan=Plan(goal=q.raw, steps=[step], created_by="template:service_status"))


class AppStatusTemplate(GoalTemplate):
    name = "app_status"
    request_class = RequestClass.APPLICATION

    def match(self, q: Query, rc: RouteContext) -> Match | None:
        t = _status_target(q)
        if t is None:
            return None
        name, explicit = t
        if explicit or name in KNOWN_SERVICES:
            return None
        return Match(0.82, {"query": name})

    def build(self, q: Query, m: Match, rc: RouteContext) -> Built:
        step = Step(id="s1", tool="apps.status", arguments={"query": m.slots["query"]},
                    description=f"is {m.slots['query']} running")
        return Built(plan=Plan(goal=q.raw, steps=[step], created_by="template:app_status"))


_PORT = re.compile(r"\bport\s+(?P<p>\d{1,5})\b|\b(?:on|:)(?P<p2>\d{2,5})\b", re.I)


class PortOwnerTemplate(GoalTemplate):
    name = "port_owner"
    request_class = RequestClass.SYSTEM

    def match(self, q: Query, rc: RouteContext) -> Match | None:
        if not q.has("port"):
            m2 = re.search(r"\blistening\s+on\s+(\d{2,5})\b", q.low)
            if not m2:
                return None
            port = int(m2.group(1))
        else:
            m = re.search(r"\bport\s+(\d{1,5})\b", q.low)
            if not m:
                return None
            port = int(m.group(1))
        if not q.has("process", "using", "uses", "use", "listening", "owner", "owns", "holds", "who", "what",
                     "which", "occupying", "bound"):
            return None
        if not 1 <= port <= 65535:
            return Match(0.92, {"port": None})
        return Match(0.92, {"port": port, "proto": "udp" if q.has("udp") else "tcp"})

    def build(self, q: Query, m: Match, rc: RouteContext) -> Built:
        if m.slots["port"] is None:
            return Built(clarification="That is not a valid port number (1-65535).")
        step = Step(id="s1", tool="net.port_owner",
                    arguments={"port": m.slots["port"], "proto": m.slots["proto"]},
                    description=f"find owner of port {m.slots['port']}")
        return Built(plan=Plan(goal=q.raw, steps=[step], created_by="template:port_owner"))


class ProcessListTemplate(GoalTemplate):
    name = "process_list"
    request_class = RequestClass.SYSTEM

    def match(self, q: Query, rc: RouteContext) -> Match | None:
        if q.has("port"):
            return None
        listing = q.has("processes", "running processes", "process list", "top processes", "tasks running")
        heavy = q.has("most cpu", "most memory", "most ram", "using the most", "uses the most", "hogging")
        if not (listing or heavy):
            return None
        sort = "cpu" if q.has("cpu", "processor") else "name" if q.has("alphabetical", "by name") else "memory"
        return Match(0.88, {"sort_by": sort})

    def build(self, q: Query, m: Match, rc: RouteContext) -> Built:
        step = Step(id="s1", tool="process.list", arguments={"limit": 15, "sort_by": m.slots["sort_by"]},
                    description="list processes")
        return Built(plan=Plan(goal=q.raw, steps=[step], created_by="template:process_list"))


_QUOTED = r"\"[^\"]+\"|'[^']+'|`[^`]+`"
_FIND = re.compile(
    rf"^(?:please\s+)?(?:find|locate|search\s+for|look\s+for|where\s+is|where's)\s+(?:me\s+)?(?:all\s+)?(?:my\s+|the\s+|a\s+)?"
    rf"(?P<n>{_QUOTED}|[\w.\-*? ]+?)\s*(?P<noun>repository|repositories|repo|repos|folder|folders|directory|"
    rf"directories|project|file|files)?(?:\s+(?:named|called))?"
    rf"(?:\s+(?:in|under|inside|within)\s+(?P<root>{_QUOTED}|[~./\\][^\s]*|[A-Za-z]:[\\/][^\s]*))?\s*[?.!]*$", re.I)
_FIND_NAMED = re.compile(
    rf"^(?:please\s+)?(?:find|locate|search\s+for|look\s+for)\s+(?:all\s+)?(?P<noun>files?|folders?|directories)\s+"
    rf"(?:named|called|matching)\s+(?P<n>{_QUOTED}|[\w.\-*?]+)"
    rf"(?:\s+(?:in|under|inside|within)\s+(?P<root>{_QUOTED}|[~./\\][^\s]*|[A-Za-z]:[\\/][^\s]*))?\s*[?.!]*$", re.I)


class FileSearchTemplate(GoalTemplate):
    name = "filesystem_search"
    request_class = RequestClass.FILESYSTEM

    def match(self, q: Query, rc: RouteContext) -> Match | None:
        m = _FIND_NAMED.match(q.raw)
        if m is None:
            m = _FIND.match(q.raw)
            if m is None or not m.group("noun"):
                return None  # without a file-ish noun this could be research ("find the latest news")
        name = m.group("n").strip().strip("\"'`").strip()
        if not name or name.lower() in {"my", "the", "a", "all"}:
            return None
        noun = (m.group("noun") or "").lower()
        kind = "dir" if noun.startswith(("repo", "folder", "director", "project")) else \
            "file" if noun.startswith("file") else "any"
        root = (m.group("root") or "~").strip("\"'`")
        return Match(0.9, {"pattern": name.replace(" ", "*") if " " in name else name, "kind": kind,
                           "root": root})

    def build(self, q: Query, m: Match, rc: RouteContext) -> Built:
        step = Step(id="s1", tool="fs.search", arguments={
            "pattern": m.slots["pattern"], "root": m.slots["root"], "kind": m.slots["kind"]},
            description=f"search for {m.slots['pattern']} under {m.slots['root']}")
        return Built(plan=Plan(goal=q.raw, steps=[step], created_by="template:filesystem_search"))


# A Windows drive path may contain spaces (C:\Users\Jane Doe\...): matched lazily up to the trailing punctuation.
_READ = re.compile(
    rf"^(?:please\s+)?(?:read|cat|print|type|show(?:\s+me)?|display|view)\s+(?:the\s+)?(?:contents?\s+of\s+)?(?:the\s+)?"
    rf"(?:file\s+)?(?P<p>{_QUOTED}|~[^\s]*|[A-Za-z]:[\\/][^\r\n\x22\x27`<>|*?]+?|[\w.\-]*[/\\][^\s]*|[\w\-]+\.[A-Za-z0-9]{{1,6}})\s*[?.!]*$",
    re.I)


class FileReadTemplate(GoalTemplate):
    name = "filesystem_read"
    request_class = RequestClass.FILESYSTEM

    def match(self, q: Query, rc: RouteContext) -> Match | None:
        m = _READ.match(q.raw)
        if not m:
            return None
        return Match(0.9, {"path": m.group("p").strip("\"'`")})

    def build(self, q: Query, m: Match, rc: RouteContext) -> Built:
        step = Step(id="s1", tool="fs.read", arguments={"path": m.slots["path"]},
                    description=f"read {m.slots['path']}")
        return Built(plan=Plan(goal=q.raw, steps=[step], created_by="template:filesystem_read"))


_NOTE_TEXT = re.compile(
    r"^(?:please\s+)?(?:(?:write|add|make|take|save|create)\s+(?:a\s+|this\s+)?note|note(?:\s+to\s+self)?|"
    r"(?:add|save|write)\s+(?:this\s+)?(?:to|in)\s+my\s+notes?)\s*(?:that|:|-|—)?\s*(?P<t>.*)$", re.I)
_SAVE_THAT = re.compile(r"^(?:please\s+)?(?:save|write|add|put)\s+(?:that|it|this)\s+(?:to|in|into)\s+my\s+notes?\s*[.!]*$", re.I)


class NotesTemplate(GoalTemplate):
    name = "notes_write"
    request_class = RequestClass.FILESYSTEM

    def match(self, q: Query, rc: RouteContext) -> Match | None:
        if _SAVE_THAT.match(q.raw):
            return Match(0.9, {"text": None})
        m = _NOTE_TEXT.match(q.raw)
        if not m:
            return None
        return Match(0.93, {"text": m.group("t").strip() or None})

    def build(self, q: Query, m: Match, rc: RouteContext) -> Built:
        text = m.slots.get("text")
        if not text:
            return Built(clarification=(
                "Tell me the text to save, for example: note: buy milk. (Saving the previous result by "
                "reference needs the context/memory milestone and is not implemented.)"))
        step = Step(id="s1", tool="notes.write", arguments={"text": str(text)}, description="save a note")
        return Built(plan=Plan(goal=q.raw, steps=[step], created_by="template:notes_write"))
