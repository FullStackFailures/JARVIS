"""Privilege broker INTERFACE (Milestone 1: interface and policy boundary only).

No elevated execution exists in this milestone. The default broker always reports
itself unavailable, and the policy engine DENIES any tool that requires
``priv.elevate``. The implementation is scheduled for Milestone 13.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from typing import Any

from pydantic import BaseModel, ConfigDict


class PrivilegedOp(BaseModel):
    model_config = ConfigDict(extra="forbid")
    op: str
    arguments: dict[str, Any] = {}


class BrokerStatus(BaseModel):
    model_config = ConfigDict(extra="forbid")
    available: bool
    reason: str | None = None
    grant_active: bool = False


class PrivilegeBroker(ABC):
    @abstractmethod
    def status(self) -> BrokerStatus: ...

    @abstractmethod
    def execute(self, op: PrivilegedOp) -> dict[str, Any]:
        """Run one typed, individually approved privileged operation."""


class UnavailableBroker(PrivilegeBroker):
    REASON = "privilege broker is not implemented in Milestone 1 (scheduled for Milestone 13)"

    def status(self) -> BrokerStatus:
        return BrokerStatus(available=False, reason=self.REASON)

    def execute(self, op: PrivilegedOp) -> dict[str, Any]:
        raise PermissionError(self.REASON)
