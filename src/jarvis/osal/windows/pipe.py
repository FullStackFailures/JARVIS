"""Windows named-pipe listener with an owner-only DACL, plus the peer-identity check.

STATUS: NOT VERIFIED on Windows. The control flow here is unit-tested on Linux against fake collaborators
(labelled FAKE_WINAPI in the tests); that proves ordering/cleanup logic only. Run the windows_only tests on
Windows (CI or docs/WINDOWS_VERIFICATION.md) for real evidence.

Why not ``multiprocessing.connection.Listener``? Its ``PipeListener`` calls ``CreateNamedPipe`` with a NULL
SECURITY_ATTRIBUTES, so the pipe gets the default DACL (which grants read access to Everyone/Anonymous). The class below
mirrors the stdlib listener's accept loop (so ``PipeConnection`` framing is unchanged) but creates each pipe
instance through ``SecurityApi.create_secure_pipe`` with the owner-only descriptor.
"""

from __future__ import annotations

import os
import threading
from typing import Any

from jarvis.osal.types import OsalError
from jarvis.osal.windows.winsec import SecurityApi

ERROR_NO_DATA = 232


class SecurePipeListener:
    def __init__(self, address: str, sddl: str, api: SecurityApi, *, winapi: Any = None,
                 connection_factory: Any = None) -> None:
        if winapi is None:
            import _winapi as winapi  # Windows-only stdlib module; imported lazily
        if connection_factory is None:
            from multiprocessing import connection as _mpc

            connection_factory = _mpc.PipeConnection  # type: ignore[attr-defined,unused-ignore]  # Windows only
        self._address, self._sddl, self._api = address, sddl, api
        self._win, self._conn_cls = winapi, connection_factory
        self._lock = threading.Lock()
        self._closed = False
        # FILE_FLAG_FIRST_PIPE_INSTANCE: fail (rather than join) if someone already owns this name.
        self._queue: list[int] = [api.create_secure_pipe(address, sddl, first=True)]

    def accept(self) -> Any:
        with self._lock:
            if self._closed:
                raise OSError("listener is closed")
            self._queue.append(self._api.create_secure_pipe(self._address, self._sddl, first=False))
            handle = self._queue.pop(0)
        try:
            ov = self._win.ConnectNamedPipe(handle, overlapped=True)
        except OSError as exc:
            if getattr(exc, "winerror", None) != ERROR_NO_DATA:  # NO_DATA: client already connected and left
                self._api.close_handle(handle)
                raise
        else:
            try:
                self._win.WaitForMultipleObjects([ov.event], False, self._win.INFINITE)
            except BaseException:
                ov.cancel()
                ov.GetOverlappedResult(True)  # the OVERLAPPED must outlive the cancelled I/O
                self._api.close_handle(handle)
                raise
            _, err = ov.GetOverlappedResult(True)
            if err != 0:
                self._api.close_handle(handle)
                raise OSError(f"ConnectNamedPipe failed (Win32 error {err})")
        return self._conn_cls(handle)

    def close(self) -> None:
        with self._lock:
            if self._closed:
                return
            self._closed = True
            pending, self._queue = self._queue, []
        for h in pending:
            self._api.close_handle(h)


def verify_peer(api: SecurityApi, pipe_handle: int, own_sid: str) -> bool | None:
    """Is the process on the other end of ``pipe_handle`` (a SERVER-end handle) owned by ``own_sid``?

    True/False when determined; None when the client PID or its token could not be queried (callers fail closed).
    Residual risk: PID reuse between the lookup and the query (tiny window; the DACL and the token handshake are
    the primary controls, this is the defence-in-depth identity check)."""
    try:
        pid = api.client_pid(pipe_handle)
    except OsalError:
        return None
    if pid == os.getpid():
        return True
    sid = api.process_user_sid(pid)
    if sid is None:
        return None
    return sid == own_sid
