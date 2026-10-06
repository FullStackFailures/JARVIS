from __future__ import annotations

import re

from jarvis.brain.lexicon import Match, Query
from jarvis.brain.templates.base import Built, GoalTemplate, RouteContext
from jarvis.core.models import RequestClass

_TAIL = r"(?:\s+jarvis)?\s*[!.?,]*\s*$"
_PATTERNS: list[tuple[str, re.Pattern[str]]] = [
    ("greeting", re.compile(r"^(?:hello|hi|hey|yo|good (?:morning|afternoon|evening)|greetings)" + _TAIL)),
    ("identity", re.compile(r"^(?:who|what) are you" + _TAIL)),
    ("how_are_you", re.compile(r"^how are you(?: doing)?(?: today)?" + _TAIL)),
    ("thanks", re.compile(r"^(?:thanks|thank you|cheers|thx)(?: a lot| very much)?" + _TAIL)),
    ("capabilities", re.compile(r"^(?:what can you do|what do you do|help|what are your capabilities)" + _TAIL)),
    ("backend", re.compile(
        r"^(?:which|what) (?:model|backend|brain|ai|intelligence)(?:\s+are you)?(?:\s+(?:using|running|on))?" + _TAIL)),
    ("last_task", re.compile(r"^(?:what did you (?:just )?do|what happened|why did that fail)" + _TAIL)),
    ("running", re.compile(r"^(?:what(?:'s| is| are you) (?:running|doing)(?: right now)?|status)" + _TAIL)),
]


class ConversationTemplate(GoalTemplate):
    name = "conversation"
    request_class = RequestClass.CONVERSATION

    def match(self, q: Query, rc: RouteContext) -> Match | None:
        text = q.low.strip()
        for kind, pat in _PATTERNS:
            if pat.match(text):
                return Match(0.97, {"kind": kind})
        return None

    def build(self, q: Query, m: Match, rc: RouteContext) -> Built:
        return Built(reply_kind=str(m.slots["kind"]))
