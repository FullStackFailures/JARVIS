"""Per-run IPC auth token. The daemon writes it (user-only file); local clients read it.

The token is the shared secret of the mutual HMAC handshake (``ipc/handshake.py``), so a process that cannot read
the file cannot authenticate. The directory and the file are restricted to the current user through
``OSAdapter.restrict_to_current_user`` (mode 0700/0600 on POSIX; a protected owner-only DACL on Windows, applied to
the file BEFORE the secret is written to it). The Windows part is NOT VERIFIED until the windows_only tests run there.
"""

from __future__ import annotations

import contextlib
import os
import secrets
from pathlib import Path

from jarvis.osal.base import OSAdapter
from jarvis.osal.host import IS_POSIX

TOKEN_FILE = "jarvisd.token"


def write_token(run_dir: Path, osal: OSAdapter | None = None) -> bytes:
    run_dir.mkdir(parents=True, exist_ok=True)
    if osal is not None:
        osal.restrict_to_current_user(run_dir, directory=True)
    elif IS_POSIX:
        with contextlib.suppress(OSError):
            os.chmod(run_dir, 0o700)
    token = secrets.token_hex(32).encode("ascii")
    path = run_dir / TOKEN_FILE
    tmp = run_dir / (TOKEN_FILE + ".tmp")
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    try:
        with os.fdopen(fd, "wb") as fh:
            if osal is not None:
                osal.restrict_to_current_user(tmp)  # lock the (still empty) file down BEFORE the secret lands in it
            elif IS_POSIX:
                os.chmod(tmp, 0o600)
            fh.write(token)
        os.replace(tmp, path)
    except BaseException:
        with contextlib.suppress(OSError):
            tmp.unlink()
        raise
    return token


def read_token(run_dir: Path) -> bytes | None:
    try:
        raw = (run_dir / TOKEN_FILE).read_bytes().strip()
    except OSError:
        return None
    return raw or None


def remove_token(run_dir: Path) -> None:
    with contextlib.suppress(OSError):
        (run_dir / TOKEN_FILE).unlink()
