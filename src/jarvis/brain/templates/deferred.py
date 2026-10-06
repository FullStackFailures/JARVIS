"""Requests for capabilities that exist in the architecture but not in this milestone.

Matching these produces an explicit UNSUPPORTED answer (never a guess, never a web lookup).
"""

from __future__ import annotations

from jarvis.brain.lexicon import Match, Query
from jarvis.brain.templates.base import Built, GoalTemplate, RouteContext
from jarvis.core.models import RequestClass

# (capability, milestone, trigger phrases)
DEFERRED: list[tuple[str, str, tuple[str, ...]]] = [
    ("desktop control (windows, keyboard, mouse, clipboard)", "Milestone 6",
     ("close", "quit", "minimize", "maximize", "resize", "switch window", "switch to", "click", "press",
      "type", "clipboard", "copy that", "paste", "kill")),
    ("browser automation", "Milestone 7",
     ("youtube", "google", "search for", "search the web", "browse", "website", "url", "github",
      "navigate", "full screen", "fullscreen", "play")),
    ("vision (screenshots, OCR, reading the screen)", "Milestone 9",
     ("screenshot", "my screen", "on screen", "ocr")),
    ("voice interaction", "Milestone 10", ("listen", "speak", "say it", "wake word")),
    ("research and knowledge retrieval", "Milestone 11",
     ("latest news", "research", "news about", "summarize the news", "find information")),
    ("scheduling and reminders", "Milestone 12",
     ("remind me", "every morning", "every hour", "schedule", "notify me when", "in 30 minutes")),
    ("coding agent", "Milestone 14", ("run the tests", "fix the bug", "git ", "lint", "refactor")),
    ("security-tool orchestration", "Milestone 15", ("deepsec", "scan", "vulnerability")),
    ("remote systems", "Milestone 16", ("ssh into", "remote machine", "remote host")),
    ("memory and preferences", "Milestone 8", ("remember that", "remember my", "forget that")),
]


class DeferredTemplate(GoalTemplate):
    name = "deferred_capability"
    request_class = RequestClass.UNKNOWN

    def match(self, q: Query, rc: RouteContext) -> Match | None:
        for capability, milestone, phrases in DEFERRED:
            if q.has(*phrases):
                return Match(0.45, {"capability": capability, "milestone": milestone})
        return None

    def build(self, q: Query, m: Match, rc: RouteContext) -> Built:
        return Built(unsupported=(
            f"That needs {m.slots['capability']}, which is planned for {m.slots['milestone']} and is not "
            "implemented yet. I have not done anything for this request."))
