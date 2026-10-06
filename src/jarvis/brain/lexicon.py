"""Utterance normalisation and phrase helpers shared by goal templates."""

from __future__ import annotations

import re
from dataclasses import dataclass, field

_ORDINALS = {
    "first": 1, "1st": 1, "second": 2, "2nd": 2, "third": 3, "3rd": 3, "fourth": 4, "4th": 4,
    "fifth": 5, "5th": 5, "last": -1,
}
ORDINAL_RE = re.compile(r"\b(" + "|".join(_ORDINALS) + r")\b")


def ordinal_of(text: str) -> int | None:
    m = ORDINAL_RE.search(text.lower())
    return _ORDINALS[m.group(1)] if m else None


@dataclass
class Query:
    raw: str
    low: str = field(init=False)

    def __post_init__(self) -> None:
        self.raw = self.raw.strip()
        self.low = re.sub(r"\s+", " ", self.raw.lower())

    def has(self, *phrases: str) -> bool:
        for p in phrases:
            if re.search(r"(?<![a-z0-9])" + re.escape(p) + r"(?![a-z0-9])", self.low):
                return True
        return False

    def count(self, *phrases: str) -> int:
        return sum(1 for p in phrases if self.has(p))

    @property
    def word_count(self) -> int:
        return len(re.findall(r"[a-z0-9']+", self.low))


@dataclass
class Match:
    score: float
    slots: dict[str, object] = field(default_factory=dict)


_CLAUSE_SPLIT = re.compile(r"\s*(?:;|,?\s+and then\s+|,?\s+then\s+|,?\s+and also\s+|,?\s+also\s+|\s+and\s+|,)\s*", re.I)


def split_clauses(text: str) -> list[str]:
    """Split a compound utterance on connectors; empty/one-word fragments are kept attached."""
    parts = [p.strip() for p in _CLAUSE_SPLIT.split(text) if p and p.strip()]
    return parts or [text.strip()]
