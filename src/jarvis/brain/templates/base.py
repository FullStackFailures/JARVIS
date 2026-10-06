"""Goal-template infrastructure for the Native Brain's deterministic fast path.

A template recognises one *family of goals* (not a phrase) and builds a validated Plan of
registered tools. Templates are an explicit, documented limitation: they cover known
system/app/file requests only; anything else is routed to a reasoner or reported unsupported.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass
from typing import ClassVar

from jarvis.brain.lexicon import Match, Query
from jarvis.core.context import ContextManager
from jarvis.core.models import Plan, RequestClass
from jarvis.osal.base import OSAdapter
from jarvis.osal.types import CapabilityInventory


@dataclass
class RouteContext:
    ctx: ContextManager
    osal: OSAdapter
    inventory: CapabilityInventory
    gateway_status: list[str]


@dataclass
class Built:
    """Result of building a template: exactly one of plan / reply_kind / clarification / unsupported."""

    plan: Plan | None = None
    reply_kind: str | None = None
    clarification: str | None = None
    unsupported: str | None = None
    notes: list[str] | None = None


class GoalTemplate(ABC):
    name: ClassVar[str]
    request_class: ClassVar[RequestClass]

    @abstractmethod
    def match(self, q: Query, rc: RouteContext) -> Match | None: ...

    @abstractmethod
    def build(self, q: Query, m: Match, rc: RouteContext) -> Built: ...
