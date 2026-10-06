"""OSAL abstract base: every OS-specific operation JARVIS needs goes through here.

Concrete behavior shared by both platforms (psutil-backed system queries, directory
listing, bounded subprocess execution with cancellation) lives in this base class.
Everything that genuinely differs per OS is an abstract hook implemented in
``osal/linux`` and ``osal/windows``.
"""

from __future__ import annotations

import contextlib
import ipaddress
import os
import socket
import subprocess
import threading
import time
from abc import ABC, abstractmethod
from collections.abc import Mapping, Sequence
from pathlib import Path
from typing import Any, ClassVar, Protocol

import psutil

from jarvis.common.cancel import CancelToken
from jarvis.osal.types import (
    AppEntry,
    Availability,
    CapabilityEntry,
    DirEntry,
    DirListing,
    DiskInfo,
    FileHit,
    FileSearchResult,
    IpcEndpoint,
    LaunchResult,
    MemoryInfo,
    NetAddress,
    OSInfo,
    OsalError,
    PortListener,
    PortOwnerResult,
    PrivilegeState,
    ProcessInfo,
    ProcessList,
    ProcessMatch,
    ProcessResult,
    ServiceState,
    SessionInfo,
    ShellInfo,
)


class IpcListener(Protocol):
    """What the daemon needs from a platform listener."""

    def accept(self) -> Any: ...
    def close(self) -> None: ...


class OSAdapter(ABC):
    """Platform adapter. Instances are cheap; heavy discovery is done on demand."""

    name: ClassVar[str]  # "linux" | "windows"

    def __init__(self, env: Mapping[str, str] | None = None) -> None:
        self.env: Mapping[str, str] = env if env is not None else os.environ

    # ------------------------------------------------------------------ environment
    @abstractmethod
    def detect_os(self) -> OSInfo: ...

    @abstractmethod
    def detect_shell(self) -> ShellInfo: ...

    @abstractmethod
    def detect_session(self) -> SessionInfo: ...

    @abstractmethod
    def privilege_state(self) -> PrivilegeState: ...

    @abstractmethod
    def probe_capabilities(self) -> dict[str, CapabilityEntry]:
        """Platform-specific capability entries (merged with the common ones)."""

    # ------------------------------------------------------------------ hooks
    @abstractmethod
    def system_executable_dirs(self) -> list[Path]:
        """Directories searched for allow-listed system commands (never user PATH)."""

    @abstractmethod
    def executable_suffixes(self) -> list[str]:
        """Suffixes tried when resolving a bare command name ('' on POSIX)."""

    @abstractmethod
    def is_hidden(self, directory: Path, entry_name: str) -> bool: ...

    @abstractmethod
    def popen_kwargs(self) -> dict[str, Any]:
        """Extra Popen kwargs that put the child in its own killable group."""

    @abstractmethod
    def kill_process_tree(self, proc: subprocess.Popen[bytes]) -> None: ...

    @abstractmethod
    def output_encoding(self) -> str: ...

    @abstractmethod
    def command_recipes(self) -> dict[str, list[list[str]]]:
        """Named, ordered alternative argv lists for common read-only queries."""

    @abstractmethod
    def discover_applications(self) -> tuple[list[AppEntry], list[str]]:
        """Return (apps, diagnostics)."""

    @abstractmethod
    def default_browser_id(self, apps: Sequence[AppEntry]) -> str | None: ...

    @abstractmethod
    def launch_application(self, app: AppEntry, args: Sequence[str] = ()) -> LaunchResult: ...

    @abstractmethod
    def service_state(self, name: str) -> ServiceState:
        """Query a system service by (alias-resolved) name through the native service manager."""

    @abstractmethod
    def service_aliases(self, name: str) -> list[str]:
        """Candidate native service names for a user-facing name (e.g. ssh -> sshd/ssh)."""

    @abstractmethod
    def ipc_endpoint(self, run_dir: Path, discriminator: str) -> IpcEndpoint:
        """Local IPC endpoint for jarvisd (unix socket under ``run_dir`` / per-user named pipe)."""

    @abstractmethod
    def create_ipc_listener(self, endpoint: IpcEndpoint, backlog: int = 8) -> IpcListener:
        """Bind the endpoint with owner-only access control and return a listener whose ``accept()`` yields
        raw (unauthenticated) ``multiprocessing.connection.Connection`` objects."""

    @abstractmethod
    def peer_is_current_user(self, fd: int) -> bool | None:
        """For an accepted local-IPC connection (``Connection.fileno()``: fd on POSIX, handle on Windows):
        True/False if the peer's identity could be checked and matches/does not match this user;
        None if it could not be determined (callers must then fail closed unless configured otherwise)."""

    @abstractmethod
    def restrict_to_current_user(self, path: Path, *, directory: bool = False) -> bool:
        """Make ``path`` accessible to the current user only. Returns True when the restriction was applied
        by the OS mechanism (mode bits / DACL); raises OsalError if it could not be applied."""

    # ------------------------------------------------------------------ system queries
    def hostname(self) -> dict[str, str]:
        host = socket.gethostname()
        try:
            fqdn = socket.getfqdn()
        except OSError:
            fqdn = host
        return {"hostname": host, "fqdn": fqdn or host}

    def memory(self) -> MemoryInfo:
        vm = psutil.virtual_memory()
        try:
            sw = psutil.swap_memory()
            swap_total, swap_used = int(sw.total), int(sw.used)
        except (OSError, RuntimeError):  # some sandboxes have no swap accounting
            swap_total = swap_used = 0
        return MemoryInfo(
            total=int(vm.total),
            available=int(vm.available),
            used=int(vm.total - vm.available),
            percent=float(vm.percent),
            swap_total=swap_total,
            swap_used=swap_used,
        )

    def disk_usage(self, path: Path) -> DiskInfo:
        try:
            usage = psutil.disk_usage(str(path))
        except FileNotFoundError as exc:
            raise OsalError("not_found", f"path does not exist: {path}") from exc
        except PermissionError as exc:
            raise OsalError("permission", f"permission denied: {path}") from exc
        except OSError as exc:
            raise OsalError("failed", f"cannot read disk usage for {path}: {exc}") from exc
        return DiskInfo(
            path=str(path),
            total=int(usage.total),
            used=int(usage.used),
            free=int(usage.free),
            percent=float(usage.percent),
        )

    def partitions(self) -> list[DiskInfo]:
        out: list[DiskInfo] = []
        for part in psutil.disk_partitions(all=False):
            try:
                u = psutil.disk_usage(part.mountpoint)
            except OSError:
                continue
            out.append(
                DiskInfo(path=part.mountpoint, total=int(u.total), used=int(u.used),
                         free=int(u.free), percent=float(u.percent))
            )
        return out

    def command_environment(self) -> dict[str, str]:
        """Environment for child processes started by terminal tools."""
        return dict(self.env)

    def cpu_info(self) -> dict[str, Any]:
        return {
            "logical": psutil.cpu_count(logical=True),
            "physical": psutil.cpu_count(logical=False),
            "percent": psutil.cpu_percent(interval=0.1),
        }

    def uptime_seconds(self) -> float:
        return max(0.0, time.time() - psutil.boot_time())

    def network_addresses(self) -> list[NetAddress]:
        stats = {}
        with contextlib.suppress(OSError):
            stats = psutil.net_if_stats()
        out: list[NetAddress] = []
        for iface, addrs in sorted(psutil.net_if_addrs().items()):
            is_up = bool(stats[iface].isup) if iface in stats else True
            for a in addrs:
                if a.family == socket.AF_INET:
                    fam = "ipv4"
                elif a.family == socket.AF_INET6:
                    fam = "ipv6"
                else:
                    continue
                raw = a.address.split("%", 1)[0]
                try:
                    ip = ipaddress.ip_address(raw)
                except ValueError:
                    continue
                out.append(
                    NetAddress(
                        interface=iface,
                        family=fam,  # type: ignore[arg-type]
                        address=raw,
                        netmask=a.netmask,
                        is_loopback=ip.is_loopback,
                        is_link_local=ip.is_link_local,
                        is_up=is_up,
                    )
                )
        return out

    def primary_ipv4(self, addresses: Sequence[NetAddress] | None = None) -> str | None:
        """Outbound IPv4 via the routing table (UDP connect sends no packets)."""
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        try:
            sock.settimeout(1.0)
            sock.connect(("192.0.2.1", 9))
            candidate = sock.getsockname()[0]
            if candidate and not candidate.startswith("127."):
                return str(candidate)
        except OSError:
            pass
        finally:
            sock.close()
        for a in addresses if addresses is not None else self.network_addresses():
            if a.family == "ipv4" and a.is_up and not a.is_loopback and not a.is_link_local:
                return a.address
        return None

    # ------------------------------------------------------------------ filesystem
    def list_directory(self, path: Path, *, show_hidden: bool, max_entries: int) -> DirListing:
        try:
            with os.scandir(path) as it:
                raw = list(it)
        except FileNotFoundError as exc:
            raise OsalError("not_found", f"no such directory: {path}") from exc
        except NotADirectoryError as exc:
            raise OsalError("invalid", f"not a directory: {path}") from exc
        except PermissionError as exc:
            raise OsalError("permission", f"permission denied: {path}") from exc
        except OSError as exc:
            raise OsalError("failed", f"cannot list {path}: {exc}") from exc

        entries: list[DirEntry] = []
        for e in raw:
            hidden = self.is_hidden(path, e.name)
            if hidden and not show_hidden:
                continue
            try:
                if e.is_symlink():
                    etype = "symlink"
                elif e.is_dir(follow_symlinks=False):
                    etype = "dir"
                elif e.is_file(follow_symlinks=False):
                    etype = "file"
                else:
                    etype = "other"
                st = e.stat(follow_symlinks=False)
                size = int(st.st_size) if etype == "file" else None
                modified = float(st.st_mtime)
            except OSError:
                etype, size, modified = "other", None, None
            entries.append(
                DirEntry(
                    name=e.name,
                    type=etype,  # type: ignore[arg-type]
                    size=size,
                    modified=modified,
                    hidden=hidden,
                )
            )
        entries.sort(key=lambda d: (d.type != "dir", d.name.casefold()))
        total = len(entries)
        return DirListing(
            path=str(path), entries=entries[:max_entries], total=total, truncated=total > max_entries
        )

    # ------------------------------------------------------------------ executables
    def resolve_system_executable(self, name: str) -> Path | None:
        """Resolve a bare command name inside trusted system directories only."""
        if not name or any(sep in name for sep in ("/", "\\")) or name in {".", ".."}:
            return None
        for directory in self.system_executable_dirs():
            for suffix in self.executable_suffixes():
                candidate = directory / (name + suffix)
                if candidate.is_file() and os.access(candidate, os.X_OK):
                    return candidate
        return None

    def resolve_executable(self, name: str) -> Path | None:
        """Resolve via the user's PATH (used only for approved, non-allow-listed commands)."""
        import shutil

        if any(sep in name for sep in ("/", "\\")):
            p = Path(name)
            return p if p.is_absolute() and p.is_file() and os.access(p, os.X_OK) else None
        found = shutil.which(name, path=self.env.get("PATH"))
        return Path(found) if found else None

    # ------------------------------------------------------------------ processes
    def find_processes(self, names: Sequence[str]) -> list[ProcessMatch]:
        wanted = {n.lower() for n in names if n}
        out: list[ProcessMatch] = []
        if not wanted:
            return out
        for p in psutil.process_iter(["pid", "name", "exe", "status"]):
            try:
                info = p.info
                pname = (info.get("name") or "").lower()
                exe = info.get("exe") or ""
                exe_base = Path(exe).name.lower() if exe else ""
                stems = {pname, exe_base, pname.removesuffix(".exe"), exe_base.removesuffix(".exe")}
                if stems & wanted:
                    out.append(
                        ProcessMatch(
                            pid=int(info["pid"]),
                            name=info.get("name") or "",
                            exe=exe or None,
                            status=info.get("status"),
                        )
                    )
            except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
                continue
        return out

    def list_processes(self, *, limit: int = 50, sort_by: str = "memory", name_filter: str | None = None
                       ) -> ProcessList:
        rows: list[ProcessInfo] = []
        own = os.getpid()
        want = name_filter.lower() if name_filter else None
        for p in psutil.process_iter(["pid", "name", "username", "status", "memory_info", "exe"]):
            try:
                info = p.info
                name = info.get("name") or ""
                if want and want not in name.lower():
                    continue
                mem = info.get("memory_info")
                rows.append(ProcessInfo(
                    pid=int(info["pid"]), name=name, user=info.get("username"), status=info.get("status"),
                    memory_rss=int(mem.rss) if mem is not None else None, exe=info.get("exe") or None,
                ))
            except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
                continue
        if sort_by == "memory":
            rows.sort(key=lambda r: r.memory_rss or 0, reverse=True)
        elif sort_by == "cpu":
            # one short sampling pass for the top candidates only (cpu_percent needs an interval)
            top = sorted(rows, key=lambda r: r.memory_rss or 0, reverse=True)[: max(limit * 3, 30)]
            procs = {}
            for r in top:
                with contextlib.suppress(psutil.Error):
                    pr = psutil.Process(r.pid)
                    pr.cpu_percent(None)
                    procs[r.pid] = pr
            time.sleep(0.2)
            for r in top:
                pr = procs.get(r.pid)
                if pr is not None:
                    with contextlib.suppress(psutil.Error):
                        r.cpu_percent = pr.cpu_percent(None)
            rows = sorted(top, key=lambda r: r.cpu_percent or 0.0, reverse=True)
        else:
            rows.sort(key=lambda r: (r.name.lower(), r.pid))
        total = len(rows)
        return ProcessList(processes=rows[:limit], total=total, truncated=total > limit,
                           own_pid_included=any(r.pid == own for r in rows[:limit]))

    def port_owner(self, port: int, proto: str = "tcp") -> PortOwnerResult:
        """Who holds ``port``? Uses psutil; non-privileged callers may not see other users' PIDs,
        in which case ``visibility`` is ``partial`` rather than pretending nobody owns the port."""
        listeners: list[PortListener] = []
        partial = False
        note: str | None = None
        try:
            conns = psutil.net_connections(kind="inet")
        except (psutil.AccessDenied, PermissionError):
            conns = []
            partial = True
            note = "the OS denied access to the connection table; retry with higher privilege"
        for c in conns:
            if not c.laddr or c.laddr.port != port:
                continue
            is_tcp = c.type == socket.SOCK_STREAM
            if proto == "tcp" and not (is_tcp and c.status == psutil.CONN_LISTEN):
                continue
            if proto == "udp" and is_tcp:
                continue
            item = PortListener(proto="tcp" if is_tcp else "udp", address=str(c.laddr.ip), port=port,
                                status=c.status or None, pid=c.pid)
            if c.pid is None:
                partial = True
            else:
                try:
                    pr = psutil.Process(c.pid)
                    item.process = pr.name()
                    with contextlib.suppress(psutil.Error):
                        item.exe = pr.exe() or None
                    with contextlib.suppress(psutil.Error):
                        item.user = pr.username()
                except (psutil.NoSuchProcess, psutil.AccessDenied):
                    partial = True
            listeners.append(item)
        if not listeners and not partial and not self.privilege_state().is_elevated:
            # No listener visible and we are unprivileged: other users' sockets may be hidden.
            partial = True
            note = note or "no visible listener; sockets owned by other users may be hidden without privilege"
        if partial and note is None:
            note = "some listeners could not be attributed to a process (insufficient privilege)"
        return PortOwnerResult(port=port, listeners=listeners, visibility="partial" if partial else "full",
                               note=note)

    @staticmethod
    def listening_ports_for_pids(pids: Sequence[int]) -> list[int]:
        """TCP ports in LISTEN state held by ``pids`` (empty when the OS hides them)."""
        ports: set[int] = set()
        for pid in pids:
            try:
                for c in psutil.Process(pid).net_connections(kind="inet"):
                    if c.status == psutil.CONN_LISTEN and c.laddr:
                        ports.add(int(c.laddr.port))
            except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
                continue
        return sorted(ports)

    def search_files(
        self, root: Path, *, pattern: str, kind: str = "any", max_results: int = 50, max_depth: int = 6,
        max_examined: int = 200_000, time_limit_s: float = 8.0, cancel: CancelToken | None = None,
        skip_names: frozenset[str] = frozenset(),
    ) -> FileSearchResult:
        """Bounded, cancellable name search (case-insensitive substring, or glob if it has wildcards)."""
        import fnmatch

        needle = pattern.lower()
        is_glob = any(ch in needle for ch in "*?[")
        hits: list[FileHit] = []
        examined = 0
        stopped: str | None = None
        deadline = time.monotonic() + time_limit_s
        stack: list[tuple[Path, int]] = [(root, 0)]
        while stack and stopped is None:
            current, depth = stack.pop()
            try:
                it = os.scandir(current)
            except OSError:
                continue
            with it:
                for e in it:
                    examined += 1
                    if cancel is not None and cancel.is_set():
                        stopped = "cancelled"
                        break
                    if examined >= max_examined:
                        stopped = "examined-entry limit reached"
                        break
                    if (examined & 0xFF) == 0 and time.monotonic() > deadline:
                        stopped = "time limit reached"
                        break
                    name_l = e.name.lower()
                    if name_l in skip_names:
                        continue
                    try:
                        is_dir = e.is_dir(follow_symlinks=False)
                        is_file = e.is_file(follow_symlinks=False)
                    except OSError:
                        continue
                    matched = fnmatch.fnmatch(name_l, needle) if is_glob else needle in name_l
                    if matched and ((kind == "any" and (is_dir or is_file))
                                    or (kind == "dir" and is_dir) or (kind == "file" and is_file)):
                        size = mtime = None
                        try:
                            st = e.stat(follow_symlinks=False)
                            size, mtime = (st.st_size if is_file else None), st.st_mtime
                        except OSError:
                            pass
                        hits.append(FileHit(path=str(Path(e.path)), type="dir" if is_dir else "file",
                                            size=size, modified=mtime))
                        if len(hits) >= max_results:
                            stopped = "result limit reached"
                            break
                    if is_dir and depth < max_depth:
                        stack.append((Path(e.path), depth + 1))
        return FileSearchResult(root=str(root), hits=hits, examined=examined,
                                truncated=stopped is not None, stopped_reason=stopped)

    @staticmethod
    def pid_alive(pid: int) -> bool:
        try:
            proc = psutil.Process(pid)
            return bool(proc.is_running() and proc.status() != psutil.STATUS_ZOMBIE)
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            return False

    def run_process(
        self,
        argv: Sequence[str],
        *,
        cwd: Path,
        env: Mapping[str, str] | None,
        timeout_s: float,
        cancel: CancelToken,
        max_output_bytes: int = 65536,
    ) -> ProcessResult:
        """Run argv (never through a shell) with bounded output, timeout and cancellation."""
        started = time.monotonic()
        argv = list(argv)
        try:
            proc = subprocess.Popen(  # noqa: S603 - argv list, shell=False
                argv,
                cwd=str(cwd),
                env=dict(env) if env is not None else None,
                stdin=subprocess.DEVNULL,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                shell=False,
                **self.popen_kwargs(),
            )
        except FileNotFoundError as exc:
            raise OsalError("not_found", f"executable or working directory not found: {exc}") from exc
        except PermissionError as exc:
            raise OsalError("permission", f"permission denied starting {argv[0]}: {exc}") from exc
        except OSError as exc:
            raise OsalError("failed", f"cannot start {argv[0]}: {exc}") from exc

        buffers = {"out": bytearray(), "err": bytearray()}
        truncated = {"v": False}

        def drain(stream: Any, key: str) -> None:
            try:
                while True:
                    chunk = stream.read(4096)
                    if not chunk:
                        break
                    room = max_output_bytes - len(buffers[key])
                    if room > 0:
                        buffers[key].extend(chunk[:room])
                    if len(chunk) > room:
                        truncated["v"] = True
            except (OSError, ValueError):
                pass

        readers = [
            threading.Thread(target=drain, args=(proc.stdout, "out"), daemon=True),
            threading.Thread(target=drain, args=(proc.stderr, "err"), daemon=True),
        ]
        for t in readers:
            t.start()

        timed_out = cancelled = False
        deadline = started + timeout_s
        while proc.poll() is None:
            if cancel.is_set():
                cancelled = True
                self.kill_process_tree(proc)
                break
            if time.monotonic() >= deadline:
                timed_out = True
                self.kill_process_tree(proc)
                break
            cancel.wait(0.02)
        with contextlib.suppress(subprocess.TimeoutExpired):
            proc.wait(timeout=2.0)
        for t in readers:
            t.join(timeout=1.0)
        for stream in (proc.stdout, proc.stderr):
            with contextlib.suppress(OSError, ValueError):
                if stream:
                    stream.close()

        enc = self.output_encoding()
        return ProcessResult(
            argv=argv,
            cwd=str(cwd),
            exit_code=proc.returncode,
            stdout=bytes(buffers["out"]).decode(enc, errors="replace"),
            stderr=bytes(buffers["err"]).decode(enc, errors="replace"),
            duration_ms=int((time.monotonic() - started) * 1000),
            timed_out=timed_out,
            cancelled=cancelled,
            truncated=truncated["v"],
        )

    @staticmethod
    def reap_in_background(proc: subprocess.Popen[bytes]) -> None:
        """Wait() on a detached child so it never lingers as a zombie."""
        threading.Thread(target=proc.wait, daemon=True).start()

    # ------------------------------------------------------------------ common capability rows
    def common_capabilities(self) -> dict[str, CapabilityEntry]:
        rows: dict[str, CapabilityEntry] = {}
        for cap in ("system.info", "system.memory", "system.disk", "net.addresses", "fs.list"):
            rows[cap] = CapabilityEntry(status=Availability.AVAILABLE, implemented=True)
        rows["process.list"] = CapabilityEntry(status=Availability.AVAILABLE, implemented=True)
        rows["terminal.exec"] = CapabilityEntry(status=Availability.AVAILABLE, implemented=True)
        deferred = {
            "window.enumeration": "window management is a Milestone 6 capability",
            "input.keyboard_mouse": "desktop input control is a Milestone 6 capability",
            "clipboard": "clipboard access is a Milestone 6 capability",
            "screen.capture": "screen capture is a Milestone 9 capability",
            "audio.devices": "audio is a Milestone 10 capability",
            "notifications": "notifications are a Milestone 12 capability",
            "accessibility": "accessibility-tree access is a Milestone 6 capability",
        }
        rows["services.query"] = CapabilityEntry(
            status=Availability.DEGRADED, implemented=True,
            reason="system.service_status is implemented; reports 'unknown' (never a guess) when no service manager answers",
        )
        for cap, why in deferred.items():
            rows[cap] = CapabilityEntry(
                status=Availability.UNAVAILABLE, implemented=False, reason=why
            )
        return rows
