"""Pure parsing/mapping of ``systemctl show`` output (testable on any OS; no process execution)."""

from __future__ import annotations


def parse_show(text: str) -> dict[str, str] | None:
    out: dict[str, str] = {}
    for line in text.splitlines():
        if "=" in line:
            k, v = line.split("=", 1)
            out[k.strip()] = v.strip()
    return out if "LoadState" in out else None


def map_state(raw: dict[str, str]) -> tuple[str, bool | None, str | None]:
    """Return (state, enabled, detail). state is one of running|stopped|failed|not_found|unknown."""
    if raw.get("LoadState") == "not-found":
        return "not_found", None, "unit not found"
    active = raw.get("ActiveState", "")
    state = {"active": "running", "reloading": "running", "inactive": "stopped", "failed": "failed"}.get(
        active, "unknown")
    ufs = raw.get("UnitFileState", "")
    enabled = True if ufs.startswith("enabled") else False if ufs in {"disabled", "masked"} else None
    return state, enabled, None if state != "unknown" else f"ActiveState={active!r}"
