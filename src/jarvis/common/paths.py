from __future__ import annotations

from pathlib import Path


def resolve_path(raw: str, cwd: Path) -> Path:
    """Expand ~, anchor relative paths at cwd and resolve symlinks/'..' (non-strict)."""
    p = Path(raw).expanduser()
    if not p.is_absolute():
        p = cwd / p
    return p.resolve(strict=False)
