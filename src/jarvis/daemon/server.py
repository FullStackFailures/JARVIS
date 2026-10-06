"""jarvisd IPC server.

Trust boundary: same OS user only. Layers (all must pass):
 1. endpoint access control - unix socket 0600 in a 0700 dir (Linux); owner-only DACL, first-instance flag and
    remote-client rejection on the named pipe (Windows, NOT VERIFIED until run on Windows);
 2. peer identity - SO_PEERCRED uid (Linux) / client-PID -> token SID (Windows); undeterminable => rejected unless
    ``ipc.require_peer_identity`` is switched off;
 3. mutual HMAC handshake on the per-run token (ipc/handshake.py), run in a per-connection thread under a deadline
    with size-capped messages, so a silent or malicious local client can neither stall ``accept()`` nor exhaust it
    (``ipc.max_pending_handshakes`` bounds concurrent unauthenticated connections).
"""

from __future__ import annotations

import contextlib
import logging
import os
import threading
import time
from collections.abc import Callable
from multiprocessing.connection import Client, Connection
from pathlib import Path
from typing import Any

from pydantic import ValidationError

from jarvis import __version__
from jarvis.common.util import new_id
from jarvis.config.schema import JarvisConfig
from jarvis.core.agent import TaskHandle
from jarvis.core.approvals import ApprovalProvider
from jarvis.core.models import ApprovalRequest, ApprovalResponse, Event, Task, Utterance
from jarvis.core.runtime import Runtime
from jarvis.ipc import auth
from jarvis.ipc import protocol as P
from jarvis.ipc.client import DaemonUnavailable, IpcClient
from jarvis.ipc.handshake import HandshakeError, server_handshake
from jarvis.osal.base import IpcListener
from jarvis.osal.types import IpcEndpoint
from jarvis.security.redact import REDACTOR

log = logging.getLogger(__name__)


class AlreadyRunning(Exception):
    pass


class Session:
    """One accepted client connection."""

    def __init__(self, conn: Connection, sid: str) -> None:
        self.conn = conn
        self.id = sid
        self._send_lock = threading.Lock()
        self.closed = threading.Event()
        self.handles: dict[str, TaskHandle] = {}
        self.subscriptions: list[Callable[[Event], None]] = []

    def send(self, msg: P._Msg) -> bool:
        if self.closed.is_set():
            return False
        try:
            with self._send_lock:
                self.conn.send_bytes(P.encode(msg))
            return True
        except (OSError, ValueError):
            self.closed.set()
            return False


class _Pending:
    def __init__(self, session: Session) -> None:
        self.session = session
        self.event = threading.Event()
        self.approved = False
        self.note = ""


class IpcApprovalProvider(ApprovalProvider):
    """Asks the client that owns the task. No client / no answer / disconnect => decline (fail closed)."""

    def __init__(self, timeout_s: float = 120.0) -> None:
        self.timeout_s = timeout_s
        self._owners: dict[str, Session] = {}
        self._pending: dict[str, _Pending] = {}
        self._lock = threading.Lock()

    def bind(self, task_id: str, session: Session) -> None:
        with self._lock:
            self._owners[task_id] = session

    def unbind(self, task_id: str) -> None:
        with self._lock:
            self._owners.pop(task_id, None)

    def request(self, req: ApprovalRequest) -> ApprovalResponse:
        with self._lock:
            session = self._owners.get(req.task_id)
        if session is None or session.closed.is_set():
            return ApprovalResponse(request_id=req.id, approved=False, note="no client attached; declined (fail closed)")
        pending = _Pending(session)
        with self._lock:
            self._pending[req.id] = pending
        try:
            prompt = P.ApprovalPrompt(
                id=req.task_id, request_id=req.id, task_id=req.task_id, tool=req.tool,
                arguments=REDACTOR.scrub(dict(req.arguments)), risk=req.risk.value, reasons=list(req.reasons))
            if not session.send(prompt):
                return ApprovalResponse(request_id=req.id, approved=False, note="client disconnected; declined")
            deadline = time.monotonic() + self.timeout_s
            while not pending.event.wait(0.25):
                if session.closed.is_set():
                    return ApprovalResponse(request_id=req.id, approved=False, note="client disconnected; declined")
                if time.monotonic() > deadline:
                    return ApprovalResponse(request_id=req.id, approved=False,
                                            note=f"no answer within {self.timeout_s:.0f}s; declined (fail closed)")
            return ApprovalResponse(request_id=req.id, approved=pending.approved, note=pending.note)
        finally:
            with self._lock:
                self._pending.pop(req.id, None)

    def resolve(self, request_id: str, approved: bool, session: Session) -> bool:
        """Only the session that owns the task may answer its approval prompt."""
        with self._lock:
            pending = self._pending.get(request_id)
        if pending is None or pending.session is not session:
            return False
        pending.approved = approved
        pending.note = "approved by the requesting client" if approved else "declined by the requesting client"
        pending.event.set()
        return True


class Daemon:
    def __init__(self, runtime: Runtime, provider: IpcApprovalProvider, endpoint: IpcEndpoint, run_dir: Path) -> None:
        self.rt = runtime
        self.provider = provider
        self.endpoint = endpoint
        self.run_dir = run_dir
        self.started_at = time.time()
        self._stop = threading.Event()
        self._token = b""
        self._listener: IpcListener | None = None
        self._slots = threading.BoundedSemaphore(runtime.config.ipc.max_pending_handshakes)
        self._last_fail_audit = 0.0
        self._suppressed_fail_audits = 0
        self._sessions: set[Session] = set()
        self._slock = threading.Lock()
        self._closed = False

    # ------------------------------------------------------------------ lifecycle
    @classmethod
    def create(cls, config: JarvisConfig, *, dotenv: dict[str, str] | None = None, env: dict[str, str] | None = None,
               osal: Any = None, extra_tools: Any = (), extra_backends: Any = None,
               approval_timeout_s: float = 120.0, cwd: Path | None = None, use_keyring: bool = True) -> Daemon:
        provider = IpcApprovalProvider(approval_timeout_s)
        rt = Runtime.create(config, dotenv=dotenv, env=env, osal=osal, approvals=provider, extra_tools=extra_tools,
                            extra_backends=extra_backends, cwd=cwd, use_keyring=use_keyring)
        disc = ""
        if config.home_override:
            import hashlib

            disc = hashlib.sha1(str(rt.dirs.run).encode()).hexdigest()[:8]  # noqa: S324 - not a security use
        endpoint = rt.osal.ipc_endpoint(rt.dirs.run, disc)
        return cls(rt, provider, endpoint, rt.dirs.run)

    def _probe_existing(self) -> int | None:
        if auth.read_token(self.run_dir) is None:
            return None
        try:
            with IpcClient(self.endpoint, self.run_dir, timeout_s=2.0, handshake_timeout_s=2.0) as c:
                return c.ping().pid
        except (DaemonUnavailable, OSError, EOFError, ValueError, TimeoutError, RuntimeError):
            return None

    def serve_forever(self) -> None:
        existing = self._probe_existing()
        if existing is not None:
            raise AlreadyRunning(f"jarvisd is already running (pid {existing})")
        if self.endpoint.cleanup_path:  # stale socket from a crashed run
            with contextlib.suppress(OSError):
                os.unlink(self.endpoint.cleanup_path)
        self._token = auth.write_token(self.run_dir, self.rt.osal)
        self._listener = self.rt.osal.create_ipc_listener(self.endpoint, backlog=8)
        self.rt.audit.append("daemon.started", None, pid=os.getpid(), endpoint=self.endpoint.address,
                             family=self.endpoint.family, version=__version__,
                             permission_mode=self.rt.config.policy.mode.value)
        log.info("jarvisd listening on %s", self.endpoint.address)
        try:
            self._accept_loop()
        finally:
            self._cleanup()

    def _accept_loop(self) -> None:
        """Accept raw connections only. Authentication happens in a per-connection thread (``_admit``)."""
        assert self._listener is not None
        while not self._stop.is_set():
            try:
                conn = self._listener.accept()
            except (OSError, EOFError):
                if self._stop.is_set():
                    break
                time.sleep(0.05)
                continue
            if self._stop.is_set():
                with contextlib.suppress(OSError):
                    conn.close()
                break
            if not self._slots.acquire(blocking=False):  # too many unauthenticated connections: shed load
                self._audit_failure("ipc.rejected", reason="too many pending handshakes")
                with contextlib.suppress(OSError):
                    conn.close()
                continue
            threading.Thread(target=self._admit, args=(conn,), name="jarvisd-admit", daemon=True).start()

    def _admit(self, conn: Connection) -> None:
        """Peer identity -> handshake (deadline) -> session. Runs in its own thread; never blocks accept()."""
        released = False

        def release() -> None:
            nonlocal released
            if not released:
                released = True
                self._slots.release()

        try:
            try:
                same_user = self.rt.osal.peer_is_current_user(conn.fileno())
            except Exception:  # an adapter bug must reject the peer, never admit it
                log.exception("peer identity check crashed")
                same_user = None
            if same_user is False:
                self._audit_failure("ipc.peer_rejected", reason="peer identity differs from the daemon's user")
                conn.close()
                return
            if same_user is None and self.rt.config.ipc.require_peer_identity:
                self._audit_failure("ipc.peer_rejected", reason="peer identity could not be determined (fail closed)")
                conn.close()
                return
            try:
                server_handshake(conn, self._token, self.rt.config.ipc.handshake_timeout_s)
            except HandshakeError as exc:
                self._audit_failure("ipc.auth_failed", reason=str(exc)[:120])
                with contextlib.suppress(OSError):
                    conn.close()
                return
            if self._stop.is_set():
                conn.close()
                return
            session = Session(conn, new_id("sess"))
            with self._slock:
                self._sessions.add(session)
            self._audit_safe("ipc.session_opened", session=session.id,
                             peer_identity="verified" if same_user else "not verified (ipc.require_peer_identity=false)")
            release()  # authenticated: no longer counts against the pending-handshake cap
            self._serve_session(session)
        except Exception:
            log.exception("connection admission failed")
            with contextlib.suppress(OSError):
                conn.close()
        finally:
            release()

    def _audit_failure(self, kind: str, **payload: Any) -> None:
        """Failed-auth events are attacker-controlled volume: at most one audit row per second (with a count)."""
        now = time.monotonic()
        if now - self._last_fail_audit < 1.0:
            self._suppressed_fail_audits += 1
            return
        self._last_fail_audit = now
        suppressed, self._suppressed_fail_audits = self._suppressed_fail_audits, 0
        self._audit_safe(kind, suppressed_since_last=suppressed, **payload)

    def _audit_safe(self, kind: str, **payload: Any) -> None:
        if self._closed:
            return
        try:
            self.rt.audit.append(kind, None, **payload)
        except Exception:
            log.exception("audit write failed for %s", kind)

    def stop(self) -> None:
        if self._stop.is_set():
            return
        self._stop.set()
        self.rt.agent.cancel_all("daemon shutting down")
        if self._token:  # wake the blocking accept(): a raw connect-and-close is enough (no handshake needed)
            with contextlib.suppress(Exception):
                Client(self.endpoint.address, family=self.endpoint.family).close()

    def _cleanup(self) -> None:
        with contextlib.suppress(Exception):
            if self._listener is not None:
                self._listener.close()
        with self._slock:
            sessions = list(self._sessions)
        for s in sessions:
            s.closed.set()
            with contextlib.suppress(OSError):
                s.conn.close()
        deadline = time.monotonic() + 3.0  # let session threads finish their own audit writes first
        while time.monotonic() < deadline:
            with self._slock:
                if not self._sessions:
                    break
            time.sleep(0.02)
        auth.remove_token(self.run_dir)
        if self.endpoint.cleanup_path:
            with contextlib.suppress(OSError):
                os.unlink(self.endpoint.cleanup_path)
        self._audit_safe("daemon.stopped", pid=os.getpid())
        self._closed = True
        self.rt.close()

    # ------------------------------------------------------------------ session handling
    def _serve_session(self, s: Session) -> None:
        try:
            while not s.closed.is_set():
                try:
                    data = s.conn.recv_bytes(P.MAX_CLIENT_FRAME)
                except (EOFError, OSError):
                    break
                try:
                    msg = P.parse_client(data)
                except (ValidationError, ValueError) as exc:
                    s.send(P.ErrorReply(id="?", code="bad_request", message=str(exc).splitlines()[0][:200]))
                    continue
                try:
                    self._dispatch(s, msg)
                except Exception as exc:
                    log.exception("ipc dispatch failed")
                    s.send(P.ErrorReply(id=msg.id, code="internal", message=f"{type(exc).__name__}"))
        finally:
            self._close_session(s)

    def _close_session(self, s: Session) -> None:
        s.closed.set()
        for h in list(s.handles.values()):  # a vanished client must not leave work running
            if not h.done:
                h.cancel("client disconnected")
        for fn in s.subscriptions:
            self.rt.events.unsubscribe(fn)
        with self._slock:
            self._sessions.discard(s)
        with contextlib.suppress(OSError):
            s.conn.close()
        self._audit_safe("ipc.session_closed", session=s.id)

    def _dispatch(self, s: Session, msg: P.ClientMessage) -> None:
        if isinstance(msg, P.PingRequest):
            s.send(P.Pong(id=msg.id, pid=os.getpid(), version=__version__))
        elif isinstance(msg, P.SubmitRequest):
            self._submit(s, msg)
        elif isinstance(msg, P.CancelRequest):
            n = self._cancel(msg.task_id)
            s.send(P.Ok(id=msg.id, detail={"cancelled": n}))
        elif isinstance(msg, P.ApproveRequest):
            ok = self.provider.resolve(msg.request_id, msg.approved, s)
            if not ok:
                s.send(P.ErrorReply(id=msg.id, code="unknown_approval",
                                    message="no such pending approval for this connection"))
        elif isinstance(msg, P.StatusRequest):
            s.send(P.StatusReply(id=msg.id, data=self.status_data()))
        elif isinstance(msg, P.ToolsRequest):
            s.send(P.ToolsReply(id=msg.id, tools=self.tools_data()))
        elif isinstance(msg, P.TasksRequest):
            s.send(P.TasksReply(id=msg.id, tasks=self.rt.tasks.recent(msg.limit)))
        elif isinstance(msg, P.SubscribeRequest):
            def forward(ev: Event, sid: str = msg.id) -> None:
                s.send(P.TaskEvent(id=sid, topic=ev.topic, payload=REDACTOR.scrub(ev.payload)))

            s.subscriptions.append(forward)
            self.rt.events.subscribe(msg.topic_prefix, forward)
            s.send(P.Ok(id=msg.id))
        elif isinstance(msg, P.ShutdownRequest):
            self._audit_safe("daemon.shutdown_requested", session=s.id)
            s.send(P.Ok(id=msg.id))
            threading.Thread(target=self.stop, daemon=True).start()

    def _submit(self, s: Session, msg: P.SubmitRequest) -> None:
        def on_created(task: Task) -> None:
            self.provider.bind(task.id, s)

        handle = self.rt.agent.submit(Utterance(text=msg.text, source=msg.source), on_created=on_created)
        tid = handle.task.id
        s.handles[tid] = handle
        s.send(P.SubmitAck(id=msg.id, task_id=tid))

        def finish() -> None:
            handle.wait(None)
            task = handle.task
            self.provider.unbind(tid)
            s.handles.pop(tid, None)
            s.send(P.TaskResult(
                id=msg.id, task_id=tid, outcome=task.outcome.value if task.outcome else None,
                status=task.status.value, text=task.final_response or "",
                task=REDACTOR.scrub(task.model_dump(mode="json"))))

        threading.Thread(target=finish, name=f"jarvisd-wait-{tid}", daemon=True).start()

    def _cancel(self, task_id: str | None) -> int:
        if task_id is None:
            return self.rt.agent.cancel_all("cancelled over IPC")
        with self._slock:
            sessions = list(self._sessions)
        for sess in sessions:
            h = sess.handles.get(task_id)
            if h is not None and not h.done:
                h.cancel("cancelled over IPC")
                return 1
        return 0

    # ------------------------------------------------------------------ data
    def status_data(self) -> dict[str, Any]:
        rt = self.rt
        return {
            "version": __version__,
            "daemon": {"pid": os.getpid(), "uptime_s": round(time.time() - self.started_at, 1),
                       "endpoint": self.endpoint.address, "protocol": P.PROTOCOL_VERSION},
            "backends": rt.gateway.status_lines(),
            "permission_mode": rt.config.policy.mode.value,
            "elevated_process": rt.inventory.privilege.is_elevated,
            "platform": rt.osal.name,
            "tools": len(rt.registry.names()),
            "active_tasks": len(rt.tasks.active()),
            "audit_entries": rt.audit.count(),
            "sessions": len(self._sessions),
        }

    def tools_data(self) -> list[dict[str, Any]]:
        out = []
        for t in self.rt.registry.all():
            m = t.manifest
            av = self.rt.registry.availability(m.name, self.rt.osal.name, self.rt.inventory)
            out.append({"name": m.name, "risk": m.risk.value, "timeout_ms": m.timeout_ms,
                        "cancellable": m.cancellable, "permissions": list(m.permissions),
                        "platforms": list(m.platforms), "available": av.available, "reason": av.reason})
        return out
