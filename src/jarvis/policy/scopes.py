"""Filesystem scope rules: in-scope roots, sensitive locations. Deterministic, no I/O side effects."""

from __future__ import annotations

import tempfile
from dataclasses import dataclass
from pathlib import Path

from jarvis.common.paths import resolve_path
from jarvis.common.sensitive import SENSITIVE_NAMES
from jarvis.osal.host import IS_WINDOWS

# Multi-component path fragments (lowercase, forward slashes).
SENSITIVE_FRAGMENTS = (
    "/.mozilla/firefox", "/.config/google-chrome", "/.config/chromium", "/.config/bravesoftware",
    "/appdata/roaming/mozilla/firefox/profiles", "/appdata/local/google/chrome/user data",
    "/appdata/local/microsoft/edge/user data", "/appdata/roaming/microsoft/credentials",
    "/appdata/roaming/microsoft/protect", "/etc/ssh", "/etc/ssl/private", "/windows/system32/config",
    "/proc/kcore", "/proc/self/mem", "/.config/gcloud",
)


@dataclass(frozen=True)
class PathClass:
    resolved: Path
    in_scope: bool
    sensitive: bool
    reason: str | None = None


class ScopeChecker:
    def __init__(self, roots: list[str] | None, cwd: Path) -> None:
        raw = roots or [str(Path.home()), str(cwd), tempfile.gettempdir()]
        self.roots: list[Path] = [Path(r).expanduser().resolve(strict=False) for r in raw]
        self.case_insensitive = IS_WINDOWS

    def _norm(self, p: Path) -> str:
        s = p.as_posix()
        return s.lower() if self.case_insensitive else s

    def classify(self, raw: str, cwd: Path) -> PathClass:
        resolved = resolve_path(raw, cwd)
        posix = resolved.as_posix().lower()
        parts = [p.lower() for p in resolved.parts]
        for part in parts:
            if part in SENSITIVE_NAMES:
                return PathClass(resolved, False, True, f"path component {part!r} marks a credential store")
        for frag in SENSITIVE_FRAGMENTS:
            if frag in posix:
                return PathClass(resolved, False, True, f"path is inside a sensitive location ({frag})")
        norm = self._norm(resolved)
        for root in self.roots:
            r = self._norm(root)
            if norm == r or norm.startswith(r.rstrip("/") + "/"):
                return PathClass(resolved, True, False)
        return PathClass(resolved, False, False, "path is outside the configured read scope")
