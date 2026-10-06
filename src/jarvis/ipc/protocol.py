"""IPC protocol v1: one JSON object per frame (multiprocessing.connection ``send_bytes``; no pickle).

Client -> server: ping, submit, cancel, approve, status, tools, tasks, subscribe, shutdown.
Server -> client: pong, submit_ack, approval_request, task_result, status_reply, tools_reply,
tasks_reply, event, ok, error.
Every reply echoes the request ``id``; ``approval_request`` / ``event`` / ``task_result`` carry the
``id`` of the submit that caused them.
"""

from __future__ import annotations

from typing import Annotated, Any, Literal

from pydantic import BaseModel, ConfigDict, Field, TypeAdapter

PROTOCOL_VERSION = 1
MAX_CLIENT_FRAME = 1_048_576


class _Msg(BaseModel):
    model_config = ConfigDict(extra="forbid")
    v: Literal[1] = 1
    id: str


# ---------------------------------------------------------------- client -> server
class PingRequest(_Msg):
    type: Literal["ping"] = "ping"


class SubmitRequest(_Msg):
    type: Literal["submit"] = "submit"
    text: str = Field(min_length=1, max_length=8000)
    source: Literal["text", "voice"] = "text"


class CancelRequest(_Msg):
    type: Literal["cancel"] = "cancel"
    task_id: str | None = None


class ApproveRequest(_Msg):
    type: Literal["approve"] = "approve"
    request_id: str
    approved: bool


class StatusRequest(_Msg):
    type: Literal["status"] = "status"


class ToolsRequest(_Msg):
    type: Literal["tools"] = "tools"


class TasksRequest(_Msg):
    type: Literal["tasks"] = "tasks"
    limit: int = Field(default=20, ge=1, le=200)


class SubscribeRequest(_Msg):
    type: Literal["subscribe"] = "subscribe"
    topic_prefix: str = ""


class ShutdownRequest(_Msg):
    type: Literal["shutdown"] = "shutdown"


# ---------------------------------------------------------------- server -> client
class Pong(_Msg):
    type: Literal["pong"] = "pong"
    protocol: int = PROTOCOL_VERSION
    pid: int
    version: str


class SubmitAck(_Msg):
    type: Literal["submit_ack"] = "submit_ack"
    task_id: str


class ApprovalPrompt(_Msg):
    type: Literal["approval_request"] = "approval_request"
    request_id: str
    task_id: str
    tool: str
    arguments: dict[str, Any]
    risk: str
    reasons: list[str]


class TaskResult(_Msg):
    type: Literal["task_result"] = "task_result"
    task_id: str
    outcome: str | None
    status: str
    text: str
    task: dict[str, Any]


class StatusReply(_Msg):
    type: Literal["status_reply"] = "status_reply"
    data: dict[str, Any]


class ToolsReply(_Msg):
    type: Literal["tools_reply"] = "tools_reply"
    tools: list[dict[str, Any]]


class TasksReply(_Msg):
    type: Literal["tasks_reply"] = "tasks_reply"
    tasks: list[dict[str, Any]]


class TaskEvent(_Msg):
    type: Literal["event"] = "event"
    topic: str
    payload: dict[str, Any] = Field(default_factory=dict)


class Ok(_Msg):
    type: Literal["ok"] = "ok"
    detail: dict[str, Any] = Field(default_factory=dict)


class ErrorReply(_Msg):
    type: Literal["error"] = "error"
    code: str
    message: str


ClientMessage = Annotated[
    PingRequest | SubmitRequest | CancelRequest | ApproveRequest | StatusRequest | ToolsRequest
    | TasksRequest | SubscribeRequest | ShutdownRequest,
    Field(discriminator="type"),
]
ServerMessage = Annotated[
    Pong | SubmitAck | ApprovalPrompt | TaskResult | StatusReply | ToolsReply | TasksReply | TaskEvent
    | Ok | ErrorReply,
    Field(discriminator="type"),
]

client_adapter: TypeAdapter[ClientMessage] = TypeAdapter(ClientMessage)
server_adapter: TypeAdapter[ServerMessage] = TypeAdapter(ServerMessage)


def parse_client(data: bytes | str) -> ClientMessage:
    return client_adapter.validate_json(data)


def parse_server(data: bytes | str) -> ServerMessage:
    return server_adapter.validate_json(data)


def encode(msg: BaseModel) -> bytes:
    return msg.model_dump_json().encode("utf-8")
