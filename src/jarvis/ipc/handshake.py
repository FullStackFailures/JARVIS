"""Mutual challenge-response handshake for jarvisd IPC (platform-neutral, deadline-bound).

Replaces the stdlib ``authkey`` handshake of ``multiprocessing.connection`` for two reasons:
 * it blocks without a timeout inside ``accept()`` (a connected-but-silent client could stall every other client), and
 * its messages are not size-capped before authentication.

Protocol (both sides hold the same per-run secret ``key``; nothing secret crosses the wire):

    S -> C  MAGIC || nonceS                       (32-byte random)
    C -> S  HMAC(key, "C|" || nonceS) || nonceC   (64 bytes exactly)
    S -> C  HMAC(key, "S|" || nonceC)             (server proves it knows the key: stops pipe/socket squatting)
    C -> S  b"JARVIS-OK"

Every receive waits on ``conn.poll(remaining)`` against ONE overall deadline and is capped at ``MAX_MSG`` bytes.
Role labels ("C|"/"S|") prevent reflecting one side's answer back at it. Comparison is constant-time.
Any failure raises ``HandshakeError``; the caller must close the connection.
"""

from __future__ import annotations

import hashlib
import hmac
import secrets
import time
from typing import Protocol

MAGIC = b"JARVIS-IPC/1:"
NONCE_LEN = 32
MAC_LEN = 32
MAX_MSG = 128
OK = b"JARVIS-OK"
DENIED = b"JARVIS-DENIED"


class HandshakeError(Exception):
    """Authentication failed, timed out, or the peer violated the protocol."""


class BytesConnection(Protocol):
    """The slice of ``multiprocessing.connection`` connections we use. ``Client()`` returns ``Connection`` on POSIX and
    ``Connection | PipeConnection`` when type-checking for Windows; both satisfy this structurally, so callers must not
    annotate the concrete class (that is what made ``mypy`` fail on Windows)."""

    def send_bytes(self, buf: bytes) -> None: ...
    def recv_bytes(self, maxlength: int | None = None) -> bytes: ...
    def poll(self, timeout: float | None = 0.0) -> bool: ...
    def close(self) -> None: ...


_Conn = BytesConnection


def _mac(key: bytes, label: bytes, nonce: bytes) -> bytes:
    return hmac.new(key, label + nonce, hashlib.sha256).digest()


def _recv(conn: _Conn, deadline: float, what: str) -> bytes:
    remaining = deadline - time.monotonic()
    try:
        if remaining <= 0 or not conn.poll(remaining):
            raise HandshakeError(f"timed out waiting for {what}")
        return conn.recv_bytes(MAX_MSG)
    except HandshakeError:
        raise
    except (EOFError, OSError, ValueError) as exc:  # closed, reset, or oversized/invalid frame
        raise HandshakeError(f"connection failed while waiting for {what}: {type(exc).__name__}") from exc


def _send(conn: _Conn, data: bytes) -> None:
    try:
        conn.send_bytes(data)
    except (OSError, ValueError) as exc:
        raise HandshakeError(f"connection failed while sending: {type(exc).__name__}") from exc


def server_handshake(conn: _Conn, key: bytes, timeout_s: float) -> None:
    if not key:
        raise HandshakeError("no shared secret configured")
    deadline = time.monotonic() + timeout_s
    nonce_s = secrets.token_bytes(NONCE_LEN)
    _send(conn, MAGIC + nonce_s)
    reply = _recv(conn, deadline, "client response")
    if len(reply) != MAC_LEN + NONCE_LEN:
        raise HandshakeError("malformed client response")
    mac_c, nonce_c = reply[:MAC_LEN], reply[MAC_LEN:]
    if not hmac.compare_digest(mac_c, _mac(key, b"C|", nonce_s)):
        try:
            conn.send_bytes(DENIED)
        except (OSError, ValueError):
            pass
        raise HandshakeError("client failed authentication")
    _send(conn, _mac(key, b"S|", nonce_c))
    if _recv(conn, deadline, "client confirmation") != OK:
        raise HandshakeError("client did not confirm the server proof")


def client_handshake(conn: _Conn, key: bytes, timeout_s: float) -> None:
    if not key:
        raise HandshakeError("no shared secret configured")
    deadline = time.monotonic() + timeout_s
    hello = _recv(conn, deadline, "server hello")
    if not hello.startswith(MAGIC) or len(hello) != len(MAGIC) + NONCE_LEN:
        raise HandshakeError("peer is not a jarvisd (bad hello)")
    nonce_s = hello[len(MAGIC):]
    nonce_c = secrets.token_bytes(NONCE_LEN)
    _send(conn, _mac(key, b"C|", nonce_s) + nonce_c)
    proof = _recv(conn, deadline, "server proof")
    if proof == DENIED:
        raise HandshakeError("jarvisd rejected the auth token")
    if not hmac.compare_digest(proof, _mac(key, b"S|", nonce_c)):
        raise HandshakeError("server failed to prove knowledge of the token (possible impostor)")
    _send(conn, OK)
