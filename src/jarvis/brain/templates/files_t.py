"""Filesystem goal family (read-only listing)."""

from __future__ import annotations

import re

from jarvis.brain.lexicon import Match, Query, ordinal_of
from jarvis.brain.templates.base import Built, GoalTemplate, RouteContext
from jarvis.core.models import Plan, RequestClass, Step

_HERE = {"here", "this", "current", "the current", "this folder", "this directory", "the current directory",
         "the current folder", "my current directory"}
_PATH_AFTER = re.compile(
    r"(?:\bin\b|\bof\b|\bat\b|\binside\b|\bunder\b|\bfrom\b|\bls\b|\bdir\b)\s+(?:the\s+|my\s+)?"
    r"(?P<p>\"[^\"]+\"|'[^']+'|`[^`]+`|[~./\\][^\s]*|[A-Za-z]:[\\/][^\s]*|[\w.\-]+(?:/[\w.\-]+)+)",
    re.I,
)
_HOME_WORDS = {"home": "~", "documents": "~/Documents", "downloads": "~/Downloads",
               "desktop": "~/Desktop", "pictures": "~/Pictures"}


class FilesTemplate(GoalTemplate):
    name = "filesystem_list"
    request_class = RequestClass.FILESYSTEM

    def match(self, q: Query, rc: RouteContext) -> Match | None:
        thing = q.has("files", "file", "folders", "folder", "directory", "directories", "contents")
        frame = q.has("show", "list", "display", "what", "see", "view", "ls", "dir", "whats", "what's", "browse")
        starts_ls = bool(re.match(r"^(ls|dir)\b", q.low))
        if not ((thing and frame) or starts_ls):
            return None
        if q.has("installed", "applications", "apps", "programs") and not starts_ls:
            return None
        return Match(0.85, {})

    def build(self, q: Query, m: Match, rc: RouteContext) -> Built:
        path = "."
        ordn = ordinal_of(q.low)
        if ordn is not None and q.has("folder", "directory", "one", "folders", "directories"):
            item, problem = rc.ctx.resolve_ordinal("subdir_list", ordn)
            if problem:
                return Built(clarification=f"I can't tell which folder you mean: {problem}. "
                                           "List a directory first, or give me its path.")
            path = str(item)
        else:
            raw = q.raw
            pm = _PATH_AFTER.search(raw)
            if pm:
                cand = pm.group("p").strip("\"'`")
                if cand.lower() not in _HERE:
                    path = cand
            else:
                for word, target in _HOME_WORDS.items():
                    if re.search(rf"\b(?:my|in|the)\s+{word}\b", q.low):
                        path = target
                        break
        args: dict[str, object] = {"path": path}
        if q.has("hidden", "dotfiles", "all files", "everything") or re.search(r"\bls\s+-\w*a", q.low):
            args["show_hidden"] = True
        step = Step(id="s1", tool="fs.list", arguments=args, description=f"list {path}")
        return Built(plan=Plan(goal=q.raw, steps=[step], created_by="template:filesystem_list"))
