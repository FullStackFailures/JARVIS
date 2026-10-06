"""notes.write: the only M1 tool that writes to disk. Confined to the configured notes directory."""

from __future__ import annotations

import contextlib
import hashlib
import os
import re
from datetime import datetime, UTC
from pathlib import Path
from typing import Any

from jarvis.core.models import FailureClass, Postcondition, SideEffect
from jarvis.osal.host import IS_POSIX
from jarvis.tools._manifest import build_manifest, obj
from jarvis.tools.base import Tool, ToolContext, ToolFailure, ToolOutput, Verification

_SAFE = re.compile(r"[^A-Za-z0-9._ -]+")


def safe_filename(title: str | None) -> str:
    base = _SAFE.sub("", (title or "").strip()).strip(" .-_")[:60]
    return base or datetime.now(UTC).strftime("note-%Y%m%d-%H%M%S")


class NotesWrite(Tool):
    manifest = build_manifest(
        "notes.write",
        "Write a text note into the JARVIS notes directory (never anywhere else). Creates a new file; "
        "refuses to overwrite unless append=true.",
        obj(
            {
                "text": {"type": "string", "minLength": 1, "maxLength": 65_536},
                "title": {"type": "string", "minLength": 1, "maxLength": 100},
                "append": {"type": "boolean"},
            },
            ["text"],
        ),
        obj(
            {
                "path": {"type": "string"},
                "bytes_written": {"type": "integer"},
                "sha256": {"type": "string"},
                "created": {"type": "boolean"},
            },
            ["path", "bytes_written", "sha256", "created"],
        ),
        permissions=["notes.write"],
        side_effects=[SideEffect.FS_WRITE],
        idempotent=False,
        methods=["open+write"],
        postcondition=Postcondition(kind="tool_verified",
                                    description="the file exists and its content hash matches what was written"),
        tags=["notes", "write", "save", "note"],
        examples=[{"text": "buy milk", "title": "todo"}],
    )

    def _notes_dir(self, ctx: ToolContext) -> Path:
        if ctx.notes_dir is None:
            raise ToolFailure(FailureClass.UNAVAILABLE, "no notes directory is configured")
        return ctx.notes_dir

    def execute(self, args: dict[str, Any], ctx: ToolContext) -> ToolOutput:
        root = self._notes_dir(ctx)
        name = safe_filename(args.get("title"))
        if not name.lower().endswith((".txt", ".md")):
            name += ".md"
        data = str(args["text"]).encode("utf-8")
        append = bool(args.get("append", False))
        try:
            root.mkdir(parents=True, exist_ok=True)
            if IS_POSIX:
                with contextlib.suppress(OSError):
                    os.chmod(root, 0o700)
            target = (root / name).resolve()
            if target.parent != root.resolve():
                raise ToolFailure(FailureClass.INVALID_ARGUMENTS, "note name escapes the notes directory")
            existed = target.exists()
            if existed and not append:
                raise ToolFailure(FailureClass.INVALID_ARGUMENTS,
                                  f"a note named {name!r} already exists; use append=true or another title")
            if existed and target.is_symlink():
                raise ToolFailure(FailureClass.INVALID_ARGUMENTS, "refusing to write through a symbolic link")
            payload = (b"\n" + data) if (existed and append) else data
            with target.open("ab" if append else "xb") as fh:
                fh.write(payload)
                fh.flush()
                os.fsync(fh.fileno())
        except ToolFailure:
            raise
        except OSError as exc:
            raise ToolFailure(FailureClass.TOOL_ERROR, f"cannot write note: {exc}") from exc
        return ToolOutput(
            {"path": str(target), "bytes_written": len(payload),
             "sha256": hashlib.sha256(payload).hexdigest(), "created": not existed},
            method="open+write",
        )

    def verify(self, args: dict[str, Any], output: ToolOutput, ctx: ToolContext) -> Verification | None:
        path = Path(output.data["path"])
        try:
            on_disk = path.read_bytes()
        except OSError as exc:
            return Verification(False, f"note file cannot be read back: {exc}")
        expected = str(args["text"]).encode("utf-8")
        if bool(args.get("append")) and not output.data["created"]:
            ok = on_disk.endswith(b"\n" + expected)
        else:
            ok = hashlib.sha256(on_disk).hexdigest() == output.data["sha256"]
        return Verification(ok, "file re-read; content matches" if ok else "file content does not match what was written")


TOOLS = [NotesWrite]
