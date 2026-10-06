"""Validated core data models (pydantic v2). Single source of truth for cross-module types."""

from __future__ import annotations

from enum import StrEnum
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field, field_validator

from jarvis.common.util import new_id, now
from jarvis.osal.types import CapabilityInventory

__all__ = [
    "ApprovalRequest",
    "ApprovalResponse",
    "AuditEntry",
    "CapabilityInventory",
    "Decision",
    "Entity",
    "EntityHint",
    "Event",
    "ExecMode",
    "FailureClass",
    "HealthReport",
    "ModelCapabilities",
    "ModelError",
    "ModelErrorClass",
    "ModelRequest",
    "ModelResponse",
    "Outcome",
    "PermissionMode",
    "Plan",
    "PolicyDecision",
    "Postcondition",
    "RequestClass",
    "RiskLevel",
    "SideEffect",
    "Step",
    "StepState",
    "StepStatus",
    "Task",
    "TaskStatus",
    "Taint",
    "ToolCall",
    "ToolError",
    "ToolManifest",
    "ToolResult",
    "Utterance",
]


class _Model(BaseModel):
    model_config = ConfigDict(extra="forbid")


# ---------------------------------------------------------------------------- enums
class RiskLevel(StrEnum):
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"

    @property
    def rank(self) -> int:
        return {"LOW": 0, "MEDIUM": 1, "HIGH": 2}[self.value]


class Decision(StrEnum):
    ALLOW = "ALLOW"
    ASK = "ASK"
    DENY = "DENY"


class PermissionMode(StrEnum):
    RESTRICTED = "RESTRICTED"
    NORMAL = "NORMAL"
    FULL_ACCESS = "FULL_ACCESS"


class Taint(StrEnum):
    TRUSTED = "trusted"
    UNTRUSTED = "untrusted"


class ExecMode(StrEnum):
    BACKGROUND = "background"
    FOREGROUND = "foreground"
    HYBRID = "hybrid"


class SideEffect(StrEnum):
    NONE = "none"
    FS_WRITE = "fs_write"
    NET_EGRESS = "net_egress"
    UI_INTERACTION = "ui_interaction"
    PROCESS = "process"
    SYSTEM_STATE = "system_state"
    EXTERNAL_COMM = "external_comm"


class RequestClass(StrEnum):
    CONVERSATION = "conversation"
    SYSTEM = "system"
    APPLICATION = "application"
    FILESYSTEM = "filesystem"
    TERMINAL = "terminal"
    CONTROL = "control"
    UNKNOWN = "unknown"


class TaskStatus(StrEnum):
    QUEUED = "queued"
    PLANNING = "planning"
    RUNNING = "running"
    WAITING = "waiting"
    PAUSED = "paused"
    CANCELLING = "cancelling"
    COMPLETED = "completed"
    PARTIALLY_COMPLETED = "partially_completed"
    FAILED = "failed"
    CANCELLED = "cancelled"

    @property
    def terminal(self) -> bool:
        return self in {
            TaskStatus.COMPLETED,
            TaskStatus.PARTIALLY_COMPLETED,
            TaskStatus.FAILED,
            TaskStatus.CANCELLED,
            TaskStatus.WAITING,
        }


class StepStatus(StrEnum):
    PENDING = "pending"
    READY = "ready"
    AWAITING_APPROVAL = "awaiting_approval"
    RUNNING = "running"
    EXECUTED = "executed"  # ran successfully but could not be verified
    VERIFIED = "verified"
    FAILED = "failed"
    SKIPPED = "skipped"
    CANCELLED = "cancelled"


class Outcome(StrEnum):
    """What the user is told. Never "done" unless VERIFIED."""

    VERIFIED = "VERIFIED"
    EXECUTED_UNVERIFIED = "EXECUTED (NOT VERIFIED)"
    PARTIAL = "PARTIAL"
    FAILED = "FAILED"
    CANCELLED = "CANCELLED"
    NEEDS_INPUT = "NEEDS INPUT"
    UNSUPPORTED = "UNSUPPORTED"
    REPLY = "REPLY"


class FailureClass(StrEnum):
    INVALID_ARGUMENTS = "invalid_arguments"
    POLICY_DENIED = "policy_denied"
    UNAVAILABLE = "unavailable"
    UNKNOWN_TOOL = "unknown_tool"
    NOT_FOUND = "not_found"
    PERMISSION = "permission"
    TIMEOUT = "timeout"
    CANCELLED = "cancelled"
    COMMAND_FAILED = "command_failed"
    DEPENDENCY_FAILED = "dependency_failed"
    RESOURCE_BUSY = "resource_busy"
    VERIFICATION_FAILED = "verification_failed"
    TOOL_ERROR = "tool_error"
    CONTRACT_VIOLATION = "contract_violation"
    INTERNAL = "internal"


# ---------------------------------------------------------------------------- tools
class Postcondition(_Model):
    kind: Literal["field_present", "min_items", "truthy", "equals", "tool_verified"]
    path: str = ""  # dotted path into the ToolResult, e.g. "data.apps"
    value: Any = None
    description: str = ""


_NAME_PATTERN = r"^[a-z][a-z0-9_]*(\.[a-z][a-z0-9_]*)+$"


class ToolManifest(_Model):
    name: str = Field(pattern=_NAME_PATTERN)
    version: str = "1.0.0"
    description: str = Field(min_length=10)
    tags: list[str] = Field(default_factory=list)
    input_schema: dict[str, Any]
    output_schema: dict[str, Any]
    platforms: list[Literal["linux", "windows"]] = Field(min_length=1)
    requires_capability: list[str] = Field(default_factory=list)
    methods: list[str] = Field(default_factory=list)
    risk: RiskLevel
    permissions: list[str] = Field(min_length=1)
    side_effects: list[SideEffect] = Field(min_length=1)
    idempotent: bool
    timeout_ms: int = Field(gt=0, le=600_000)
    cancellable: bool
    execution_modes: list[ExecMode] = Field(min_length=1)
    resources: list[str] = Field(default_factory=list)
    postcondition: Postcondition | None = None
    result_taint: Taint = Taint.TRUSTED
    examples: list[dict[str, Any]] = Field(default_factory=list)


class ToolCall(_Model):
    tool: str
    arguments: dict[str, Any] = Field(default_factory=dict)
    step_id: str | None = None
    task_id: str | None = None


class ToolError(_Model):
    cls: FailureClass
    message: str
    retryable: bool = False


class ToolResult(_Model):
    ok: bool
    tool: str
    step_id: str | None = None
    platform: str
    method_used: str | None = None
    data: dict[str, Any] = Field(default_factory=dict)
    error: ToolError | None = None
    duration_ms: int = 0
    started_at: float = Field(default_factory=now)
    verified: bool | None = None
    verification_note: str | None = None
    taint: Taint = Taint.TRUSTED
    attempts: int = 1

    @property
    def failure_class(self) -> FailureClass | None:
        return self.error.cls if self.error else None


class EntityHint(_Model):
    """A tool's suggestion for what the context manager should remember."""

    type: str
    value: Any
    label: str | None = None


class Entity(_Model):
    id: str = Field(default_factory=lambda: new_id("ent"))
    type: str
    value: Any
    label: str | None = None
    source_step: str | None = None
    source_task: str | None = None
    created_at: float = Field(default_factory=now)
    ttl_s: float = 600.0

    def is_stale(self, at: float | None = None) -> bool:
        return ((at if at is not None else now()) - self.created_at) > self.ttl_s


# ---------------------------------------------------------------------------- plan / task
class Step(_Model):
    id: str = Field(pattern=r"^s[0-9]+$")
    tool: str
    arguments: dict[str, Any] = Field(default_factory=dict)
    depends_on: list[str] = Field(default_factory=list)
    mode: ExecMode = ExecMode.BACKGROUND
    postcondition: Postcondition | None = None
    description: str = ""
    meta: dict[str, Any] = Field(default_factory=dict)  # planner/recovery hints, never sent to tools


class Plan(_Model):
    id: str = Field(default_factory=lambda: new_id("plan"))
    goal: str
    steps: list[Step]
    created_by: str
    assumptions: list[str] = Field(default_factory=list)
    version: int = 1


class PolicyDecision(_Model):
    decision: Decision
    risk: RiskLevel
    reasons: list[str] = Field(default_factory=list)
    approval_type: Literal["none", "once"] = "none"
    mode: PermissionMode = PermissionMode.NORMAL
    tainted: bool = False


class ApprovalRequest(_Model):
    id: str = Field(default_factory=lambda: new_id("apr"))
    task_id: str
    step_id: str
    tool: str
    arguments: dict[str, Any]
    risk: RiskLevel
    reasons: list[str]
    created_at: float = Field(default_factory=now)


class ApprovalResponse(_Model):
    request_id: str
    approved: bool
    note: str = ""


class AttemptRecord(_Model):
    tool: str
    arguments: dict[str, Any]
    ok: bool
    failure: str | None = None
    duration_ms: int = 0


class StepState(_Model):
    step_id: str
    status: StepStatus = StepStatus.PENDING
    attempts: list[AttemptRecord] = Field(default_factory=list)
    result: ToolResult | None = None
    policy: PolicyDecision | None = None
    started_at: float | None = None
    finished_at: float | None = None
    note: str | None = None


class LedgerEntry(_Model):
    step_id: str
    tool: str
    status: StepStatus
    summary: str
    ok: bool
    verified: bool | None = None


class Utterance(_Model):
    text: str
    source: Literal["text", "voice"] = "text"
    confidence: float | None = None
    lang: str | None = None
    ts: float = Field(default_factory=now)

    @field_validator("text")
    @classmethod
    def _strip(cls, v: str) -> str:
        return v.strip()


class Task(_Model):
    id: str = Field(default_factory=lambda: new_id("task"))
    goal: str
    source: Literal["text", "voice", "schedule", "event", "remote"] = "text"
    status: TaskStatus = TaskStatus.QUEUED
    request_class: RequestClass = RequestClass.UNKNOWN
    route: dict[str, Any] = Field(default_factory=dict)
    plan: Plan | None = None
    step_states: dict[str, StepState] = Field(default_factory=dict)
    ledger: list[LedgerEntry] = Field(default_factory=list)
    notes: list[str] = Field(default_factory=list)
    failures: list[str] = Field(default_factory=list)
    final_response: str | None = None
    outcome: Outcome | None = None
    permission_mode: PermissionMode = PermissionMode.NORMAL
    backend_used: str = "native"
    recoveries: int = 0
    created_at: float = Field(default_factory=now)
    finished_at: float | None = None


class Event(_Model):
    id: str = Field(default_factory=lambda: new_id("evt"))
    topic: str
    payload: dict[str, Any] = Field(default_factory=dict)
    ts: float = Field(default_factory=now)


class AuditEntry(_Model):
    seq: int
    ts: str
    task_id: str | None
    kind: str
    payload: dict[str, Any]
    prev_hash: str
    hash: str


# ---------------------------------------------------------------------------- models/gateway
class ModelCapabilities(_Model):
    backend_id: str
    model: str | None = None
    context_window: int | None = None
    supports_json_schema: bool = False
    supports_streaming: bool = False
    supports_vision: bool = False
    supports_open_planning: bool = False
    local: bool = True
    notes: list[str] = Field(default_factory=list)


class HealthReport(_Model):
    backend_id: str
    configured: bool = True
    server_reachable: bool | None = None
    model_present: bool | None = None
    generation_ok: bool | None = None
    detail: str = ""
    checked_at: float = Field(default_factory=now)

    @property
    def level(self) -> str:
        if not self.configured:
            return "NOT CONFIGURED"
        if self.server_reachable is False:
            return "UNREACHABLE"
        if self.model_present is False:
            return "MODEL MISSING"
        if self.generation_ok is True:
            return "AVAILABLE"
        if self.generation_ok is False:
            return "GENERATION FAILED"
        if self.server_reachable and self.model_present:
            return "READY (generation untested)"
        if self.server_reachable:
            return "REACHABLE"
        return "UNKNOWN"

    @property
    def usable(self) -> bool:
        return bool(self.configured and self.server_reachable and self.model_present is not False
                    and self.generation_ok is not False)


class ModelErrorClass(StrEnum):
    SERVER_UNREACHABLE = "server_unreachable"
    MODEL_MISSING = "model_missing"
    TIMEOUT = "timeout"
    BAD_RESPONSE = "bad_response"
    SCHEMA_INVALID = "schema_invalid"
    AUTH = "auth"
    RATE_LIMITED = "rate_limited"
    CAPABILITY_UNSUPPORTED = "capability_unsupported"
    PRIVACY_BLOCKED = "privacy_blocked"
    NO_BACKEND = "no_backend"
    NOT_CONFIGURED = "not_configured"
    INTERNAL = "internal"


class ModelError(_Model):
    cls: ModelErrorClass
    message: str
    retryable: bool = False
    backend_id: str | None = None


class ModelRequest(_Model):
    request_id: str = Field(default_factory=lambda: new_id("mreq"))
    task_id: str | None = None
    purpose: Literal["classify", "plan", "repair", "summarise", "chat", "health"] = "plan"
    messages: list[dict[str, str]]
    response_schema: dict[str, Any] | None = None
    max_tokens: int = 1024
    temperature: float = 0.0
    timeout_s: float = 30.0
    privacy_class: Literal["local_only", "may_leave_machine"] = "local_only"


class ModelResponse(_Model):
    request_id: str
    backend_id: str
    model: str | None = None
    ok: bool
    content: str = ""
    parsed: Any = None
    usage: dict[str, int] = Field(default_factory=dict)
    latency_ms: int = 0
    finish_reason: str | None = None
    error: ModelError | None = None
    fallbacks_tried: list[str] = Field(default_factory=list)
