"""Pure application matching/ranking used by apps.discover (unit-testable on any OS)."""

from __future__ import annotations

import re
from collections.abc import Sequence
from dataclasses import dataclass

from jarvis.osal.types import AppEntry

_WORD = re.compile(r"[a-z0-9]+")


def norm(text: str) -> str:
    return " ".join(_WORD.findall(text.lower()))


def score(app: AppEntry, query: str) -> int:
    q = norm(query)
    if not q:
        return 0
    name = norm(app.name)
    stems = {norm(s) for s in app.process_match}
    if q == name:
        return 100
    if q in stems:
        return 90
    if name.startswith(q + " ") or name.startswith(q):
        return 80
    if any(w.startswith(q) for w in name.split()):
        return 60
    if q in name:
        return 40
    q_words = set(q.split())
    if q_words and q_words <= set(name.split()):
        return 30
    return 0


@dataclass
class MatchResult:
    matches: list[AppEntry]
    preferred_id: str | None
    ambiguous: bool
    candidate_names: list[str]


_SOURCE_RANK = {"desktop_file": 0, "registry_app_paths": 0, "start_menu": 1, "path": 2}


def _pick_best(group: Sequence[AppEntry]) -> AppEntry:
    return sorted(group, key=lambda a: (_SOURCE_RANK.get(a.source, 9), a.id))[0]


def rank(
    apps: Sequence[AppEntry],
    *,
    query: str | None,
    kind: str | None,
    default_browser_id: str | None,
) -> MatchResult:
    pool = [a for a in apps if kind is None or a.kind == kind]
    if query and norm(query):
        scored = [(score(a, query), a) for a in pool]
        scored = [(s, a) for s, a in scored if s > 0]
        if not scored:
            return MatchResult([], None, False, [])
        best = max(s for s, _ in scored)
        top = [a for s, a in scored if s == best]
        matches = [a for _, a in sorted(scored, key=lambda t: (-t[0], t[1].name.casefold(), t[1].id))]
        by_name: dict[str, list[AppEntry]] = {}
        for a in top:
            by_name.setdefault(norm(a.name), []).append(a)
        if len(by_name) == 1:
            return MatchResult(matches, _pick_best(top).id, False, [])
        return MatchResult(matches, None, True, sorted({a.name for a in top}))
    if not pool:
        return MatchResult([], None, False, [])
    if kind is not None:
        if default_browser_id and kind == "browser" and any(a.id == default_browser_id for a in pool):
            return MatchResult(pool, default_browser_id, False, [])
        return MatchResult(pool, _pick_best(pool[:1]).id if len(pool) == 1 else pool[0].id, False, [])
    return MatchResult(pool, None, False, [])
