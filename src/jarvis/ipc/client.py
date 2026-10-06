"""Blocking IPC client used by the ``jarvis`` CLI (and by tests). Speaks protocol v1 only."""

from __future__ import annotations

import contextlib
import threading
from collections.abc import Callable
from multiprocessing.connection import Client
from pathlib import Path
from typing import Any

from jarvis.common.util import new_id
from jarvis.ipc import protocol as P
from jarvis.ipc.auth import read_token
from jarvis.ipc.handshake import BytesConnection, HandshakeError, client_handshake
from jarvis.osal.types import IpcEndpoint


class DaemonUnavailable(Exception):
    """jarvisd is not running / not reachable / refused authentication."""


ApprovalCallback = Callable[[P.ApprovalPrompt], bool]


class IpcClient:
    def __init__(self, endpoint: IpcEndpoint, run_dir: Path, timeout_s: float = 5.0,
                 handshake_timeout_s: float = 5.0) -> None:
        token = read_token(run_dir)
        if token is None:
            raise DaemonUnavailable("jarvisd is not running (no auth token found)")
        self._conn: BytesConnection
        try:
            self._conn = Client(endpoint.address, family=endpoint.family)  # raw; we authenticate ourselves
        except (FileNotFoundError, ConnectionRefusedError) as exc:
            raise DaemonUnavailable("jarvisd is not running (connection refused)") from exc
        except OSError as exc:
            raise DaemonUnavailable(f"cannot reach jarvisd: {exc}") from exc
        try:
            client_handshake(self._conn, token, handshake_timeout_s)
        except HandshakeError as exc:
            with contextlib.suppress(OSError):
                self._conn.close()
            raise DaemonUnavailable(f"jarvisd authentication failed: {exc}") from exc
        self._timeout = timeout_s
        self._lock = threading.Lock()

    def close(self) -> None:
        try:
            self._conn.close()
        except OSError:
            pass

    def __enter__(self) -> IpcClient:
        return self

    def __exit__(self, *exc: object) -> None:
        self.close()

    # ------------------------------------------------------------------ primitives
    def send(self, msg: P._Msg) -> None:
        with self._lock:
            self._conn.send_bytes(P.encode(msg))

    def recv(self, timeout: float | None = None) -> P.ServerMessage:
        if timeout is not None and not self._conn.poll(timeout):
            raise TimeoutError("no reply from jarvisd")
        return P.parse_server(self._conn.recv_bytes())

    def call(self, msg: P._Msg) -> P.ServerMessage:
        """Request/response for the simple, non-streaming messages."""
        self.send(msg)
        while True:
            reply = self.recv(self._timeout)
            if getattr(reply, "id", None) == msg.id:
                if isinstance(reply, P.ErrorReply):
                    raise RuntimeError(f"{reply.code}: {reply.message}")
                return reply

    # ------------------------------------------------------------------ operations
    def ping(self) -> P.Pong:
        r = self.call(P.PingRequest(id=new_id("req")))
        assert isinstance(r, P.Pong)
        return r

    def status(self) -> dict[str, Any]:
        r = self.call(P.StatusRequest(id=new_id("req")))
        assert isinstance(r, P.StatusReply)
        return r.data

    def tools(self) -> list[dict[str, Any]]:
        r = self.call(P.ToolsRequest(id=new_id("req")))
        assert isinstance(r, P.ToolsReply)
        return r.tools

    def tasks(self, limit: int = 20) -> list[dict[str, Any]]:
        r = self.call(P.TasksRequest(id=new_id("req"), limit=limit))
        assert isinstance(r, P.TasksReply)
        return r.tasks

    def cancel(self, task_id: str | None = None) -> dict[str, Any]:
        r = self.call(P.CancelRequest(id=new_id("req"), task_id=task_id))
        assert isinstance(r, P.Ok)
        return r.detail

    def shutdown(self) -> None:
        self.call(P.ShutdownRequest(id=new_id("req")))

    def ask(
        self,
        text: str,
        *,
        on_approval: ApprovalCallback | None = None,
        timeout_s: float = 300.0,
        on_interrupt_cancel: bool = True,
        source: str = "text",
    ) -> P.TaskResult:
        """Submit one request and block for its result, answering approval prompts via ``on_approval``
        (no callback => every approval is declined: fail closed)."""
        sid = new_id("req")
        self.send(P.SubmitRequest(id=sid, text=text, source=source))  # type: ignore[arg-type]
        task_id: str | None = None
        waited = 0.0
        try:
            while True:
                try:
                    msg = self.recv(0.5)
                except TimeoutError:
                    waited += 0.5
                    if waited > timeout_s:
                        raise
                    continue
                if isinstance(msg, P.ErrorReply) and msg.id == sid:
                    raise RuntimeError(f"{msg.code}: {msg.message}")
                if isinstance(msg, P.SubmitAck) and msg.id == sid:
                    task_id = msg.task_id
                elif isinstance(msg, P.ApprovalPrompt):
                    approved = bool(on_approval(msg)) if on_approval else False
                    self.send(P.ApproveRequest(id=new_id("req"), request_id=msg.request_id, approved=approved))
                elif isinstance(msg, P.TaskResult) and msg.id == sid:
                    return msg
        except KeyboardInterrupt:
            if on_interrupt_cancel and task_id:
                self.send(P.CancelRequest(id=new_id("req"), task_id=task_id))
                try:
                    while True:
                        msg = self.recv(5.0)
                        if isinstance(msg, P.TaskResult) and msg.id == sid:
                            return msg
                except TimeoutError:
                    pass
            raise
