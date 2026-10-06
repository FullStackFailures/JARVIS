"""Approval providers. The default fails closed: nothing is approved without an explicit yes."""

from __future__ import annotations

import sys
from abc import ABC, abstractmethod

from jarvis.core.models import ApprovalRequest, ApprovalResponse


class ApprovalProvider(ABC):
    @abstractmethod
    def request(self, req: ApprovalRequest) -> ApprovalResponse: ...


class DenyAllProvider(ApprovalProvider):
    """Non-interactive default: every approval request is declined."""

    def request(self, req: ApprovalRequest) -> ApprovalResponse:
        return ApprovalResponse(request_id=req.id, approved=False,
                                note="no interactive approval channel; declined (fail closed)")


class StaticProvider(ApprovalProvider):
    """Deterministic provider for tests and scripted use: approves exactly what it is told to."""

    def __init__(self, approve: bool = False) -> None:
        self.approve = approve
        self.requests: list[ApprovalRequest] = []

    def request(self, req: ApprovalRequest) -> ApprovalResponse:
        self.requests.append(req)
        return ApprovalResponse(request_id=req.id, approved=self.approve,
                                note="approved by static provider" if self.approve else "declined by static provider")


class InteractiveProvider(ApprovalProvider):
    """Prompts on the terminal. Declines when stdin is not a TTY."""

    def request(self, req: ApprovalRequest) -> ApprovalResponse:
        if not sys.stdin or not sys.stdin.isatty():
            return ApprovalResponse(request_id=req.id, approved=False,
                                    note="stdin is not interactive; declined (fail closed)")
        print(f"\nApproval required [{req.risk.value}] {req.tool}")
        print(f"  arguments: {req.arguments}")
        for r in req.reasons:
            print(f"  - {r}")
        try:
            answer = input("Approve this single action? [y/N] ").strip().lower()
        except EOFError:
            answer = ""
        return ApprovalResponse(request_id=req.id, approved=answer in {"y", "yes"},
                                note="user answered " + (answer or "<empty>"))
