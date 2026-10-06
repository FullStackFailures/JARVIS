"""Data types exchanged across the OS abstraction layer (OSAL).

This module is a leaf: it must not import anything from jarvis except jarvis.common.
"""

from __future__ import annotations

from enum import StrEnum
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field


class OsalError(Exception):
    """Structured OSAL failure. ``kind`` is one of the values below."""

    KINDS = ("not_found", "permission", "unavailable", "invalid", "failed")

    def __init__(self, kind: str, message: str) -> None:
        super().__init__(message)
        assert kind in self.KINDS, kind
        self.kind = kind
        self.message = message


class OsalUnavailable(OsalError):
    def __init__(self, message: str) -> None:
        super().__init__("unavailable", message)


class _M(BaseModel):
    model_config = ConfigDict(extra="forbid")


class Availability(StrEnum):
    AVAILABLE = "available"
    DEGRADED = "degraded"
    UNAVAILABLE = "unavailable"


class OSInfo(_M):
    system: Literal["linux", "windows"]
    release: str
    version: str
    arch: str
    distro: str | None = None
    build: str | None = None
    hostname: str


class ShellInfo(_M):
    default_shell: str | None = None
    available: dict[str, str] = Field(default_factory=dict)


class SessionInfo(_M):
    session_type: str | None = None  # x11 | wayland | tty | console | rdp | unknown
    desktop: str | None = None
    display: str | None = None
    graphical: bool = False
    init_system: str | None = None


class PrivilegeState(_M):
    is_elevated: bool
    user: str
    uid: int | None = None
    method: str
    broker: Literal["unavailable", "available"] = "unavailable"
    broker_reason: str | None = "privilege broker is deferred beyond Milestone 1"


class CapabilityEntry(_M):
    status: Availability
    implemented: bool
    reason: str | None = None


class CapabilityInventory(_M):
    os: OSInfo
    shell: ShellInfo
    session: SessionInfo
    privilege: PrivilegeState
    capabilities: dict[str, CapabilityEntry]
    apps_found: int = 0
    browsers_found: list[str] = Field(default_factory=list)
    generated_at: float

    def status_of(self, capability: str) -> Availability:
        entry = self.capabilities.get(capability)
        return entry.status if entry else Availability.UNAVAILABLE

    def reason_of(self, capability: str) -> str | None:
        entry = self.capabilities.get(capability)
        return entry.reason if entry else "capability not known on this platform"


class MemoryInfo(_M):
    total: int
    available: int
    used: int
    percent: float
    swap_total: int
    swap_used: int


class DiskInfo(_M):
    path: str
    total: int
    used: int
    free: int
    percent: float


class NetAddress(_M):
    interface: str
    family: Literal["ipv4", "ipv6"]
    address: str
    netmask: str | None = None
    is_loopback: bool = False
    is_link_local: bool = False
    is_up: bool = True


class DirEntry(_M):
    name: str
    type: Literal["file", "dir", "symlink", "other"]
    size: int | None = None
    modified: float | None = None
    hidden: bool = False


class DirListing(_M):
    path: str
    entries: list[DirEntry]
    total: int
    truncated: bool


class AppEntry(_M):
    id: str
    name: str
    kind: Literal[
        "browser", "terminal", "editor", "media", "office", "file_manager", "other"
    ] = "other"
    source: str
    exec_argv: list[str] = Field(default_factory=list)
    launch_uri: str | None = None
    launch_method: Literal["exec", "startfile", "shell_appsfolder"] = "exec"
    process_match: list[str] = Field(default_factory=list)
    default_for: list[str] = Field(default_factory=list)
    comment: str | None = None


class LaunchResult(_M):
    pid: int | None
    argv: list[str]
    launched_via: str
    note: str | None = None


class ProcessResult(_M):
    argv: list[str]
    cwd: str
    exit_code: int | None
    stdout: str
    stderr: str
    duration_ms: int
    timed_out: bool = False
    cancelled: bool = False
    truncated: bool = False
    resolved_path: str | None = None


class ProcessMatch(_M):
    pid: int
    name: str
    exe: str | None = None
    status: str | None = None


class ProcessInfo(_M):
    pid: int
    name: str
    user: str | None = None
    status: str | None = None
    cpu_percent: float | None = None
    memory_rss: int | None = None
    exe: str | None = None


class ProcessList(_M):
    processes: list[ProcessInfo]
    total: int
    truncated: bool
    own_pid_included: bool = False


class PortListener(_M):
    proto: Literal["tcp", "udp"]
    address: str
    port: int
    status: str | None = None
    pid: int | None = None
    process: str | None = None
    exe: str | None = None
    user: str | None = None


class PortOwnerResult(_M):
    port: int
    listeners: list[PortListener]
    # "full": every socket could be attributed; "partial": the OS hid some owners (needs privilege)
    visibility: Literal["full", "partial"]
    note: str | None = None


class ServiceState(_M):
    name: str
    resolved_name: str | None = None
    state: Literal["running", "stopped", "failed", "not_found", "unknown"]
    enabled: bool | None = None
    method: str
    detail: str | None = None
    raw: dict[str, Any] = Field(default_factory=dict)
    listening_ports: list[int] = Field(default_factory=list)


class FileHit(_M):
    path: str
    type: Literal["file", "dir"]
    size: int | None = None
    modified: float | None = None


class FileSearchResult(_M):
    root: str
    hits: list[FileHit]
    examined: int
    truncated: bool
    stopped_reason: str | None = None


class IpcEndpoint(_M):
    """Where jarvisd listens: a unix socket path (Linux) or a named pipe (Windows)."""

    family: Literal["AF_UNIX", "AF_PIPE"]
    address: str
    cleanup_path: str | None = None  # filesystem entry to remove on shutdown (unix socket)


def dump(model: BaseModel) -> dict[str, Any]:
    return model.model_dump(mode="json")
