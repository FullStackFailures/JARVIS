"""Linux OSAL adapter (POSIX process groups, XDG desktop entries, systemd detection)."""

from __future__ import annotations

import contextlib
import getpass
import os
import platform
import shutil
import signal
import socket
import struct
import subprocess
import sys
import time
from collections.abc import Sequence
from pathlib import Path
from typing import Any, ClassVar

from jarvis.common.cancel import CancelToken
from jarvis.osal.base import IpcListener, OSAdapter
from jarvis.osal.common.appkinds import KNOWN_APPS, PATH_SCAN_NAMES, classify, stem
from jarvis.osal.linux import systemd
from jarvis.osal.linux.desktop import exec_to_argv, parse_desktop_entry, parse_mimeapps
from jarvis.osal.types import (
    AppEntry,
    Availability,
    CapabilityEntry,
    IpcEndpoint,
    LaunchResult,
    OSInfo,
    OsalUnavailable,
    OsalError,
    PrivilegeState,
    ServiceState,
    SessionInfo,
    ShellInfo,
)


class LinuxAdapter(OSAdapter):
    name: ClassVar[str] = "linux"

    # ------------------------------------------------------------------ environment
    def detect_os(self) -> OSInfo:
        distro = None
        with contextlib.suppress(OSError, AttributeError):
            rel = platform.freedesktop_os_release()
            distro = rel.get("PRETTY_NAME") or rel.get("NAME")
        return OSInfo(
            system="linux",
            release=platform.release(),
            version=platform.version(),
            arch=platform.machine(),
            distro=distro,
            hostname=platform.node(),
        )

    def detect_shell(self) -> ShellInfo:
        available: dict[str, str] = {}
        for sh in ("bash", "zsh", "fish", "dash", "sh"):
            found = shutil.which(sh, path=self.env.get("PATH"))
            if found:
                available[sh] = found
        return ShellInfo(default_shell=self.env.get("SHELL"), available=available)

    def detect_session(self) -> SessionInfo:
        session_type = (self.env.get("XDG_SESSION_TYPE") or "").lower() or None
        wayland = bool(self.env.get("WAYLAND_DISPLAY"))
        x11 = bool(self.env.get("DISPLAY"))
        if session_type in (None, "", "unspecified"):
            session_type = "wayland" if wayland else "x11" if x11 else "tty"
        init = None
        if Path("/run/systemd/system").is_dir():
            init = "systemd"
        else:
            with contextlib.suppress(OSError):
                init = Path("/proc/1/comm").read_text().strip() or None
        return SessionInfo(
            session_type=session_type,
            desktop=self.env.get("XDG_CURRENT_DESKTOP"),
            display=self.env.get("WAYLAND_DISPLAY") or self.env.get("DISPLAY"),
            graphical=wayland or x11,
            init_system=init,
        )

    def privilege_state(self) -> PrivilegeState:
        if sys.platform == "win32":  # never true at runtime (LinuxAdapter is only created on Linux); narrows type-checking
            raise OsalUnavailable("LinuxAdapter uses POSIX-only APIs")  # of this POSIX-only body when mypy targets win32
        euid = os.geteuid()
        try:
            user = getpass.getuser()
        except (KeyError, OSError):
            user = str(euid)
        return PrivilegeState(
            is_elevated=euid == 0, user=user, uid=euid, method="euid==0"
        )

    def probe_capabilities(self) -> dict[str, CapabilityEntry]:
        rows = self.common_capabilities()
        sess = self.detect_session()
        if sess.graphical:
            rows["graphical.session"] = CapabilityEntry(
                status=Availability.AVAILABLE, implemented=True
            )
        else:
            rows["graphical.session"] = CapabilityEntry(
                status=Availability.UNAVAILABLE,
                implemented=True,
                reason="neither DISPLAY nor WAYLAND_DISPLAY is set",
            )
        rows["apps.discover"] = CapabilityEntry(status=Availability.AVAILABLE, implemented=True)
        rows["apps.launch"] = CapabilityEntry(
            status=Availability.AVAILABLE if sess.graphical else Availability.DEGRADED,
            implemented=True,
            reason=None if sess.graphical else "no graphical session: GUI apps cannot be shown",
        )
        return rows

    # ------------------------------------------------------------------ hooks
    def system_executable_dirs(self) -> list[Path]:
        return [Path(p) for p in ("/usr/local/sbin", "/usr/local/bin", "/usr/sbin", "/usr/bin", "/sbin", "/bin")]

    def executable_suffixes(self) -> list[str]:
        return [""]

    def is_hidden(self, directory: Path, entry_name: str) -> bool:
        return entry_name.startswith(".")

    def popen_kwargs(self) -> dict[str, Any]:
        return {"start_new_session": True, "close_fds": True}

    def kill_process_tree(self, proc: subprocess.Popen[bytes]) -> None:
        if sys.platform == "win32":  # never true at runtime (LinuxAdapter is only created on Linux); narrows type-checking
            raise OsalUnavailable("LinuxAdapter uses POSIX-only APIs")  # of this POSIX-only body when mypy targets win32
        try:
            pgid = os.getpgid(proc.pid)
        except ProcessLookupError:
            return
        for sig, wait in ((signal.SIGTERM, 0.3), (signal.SIGKILL, 1.0)):
            try:
                os.killpg(pgid, sig)
            except ProcessLookupError:
                return
            deadline = time.monotonic() + wait
            while time.monotonic() < deadline:
                if proc.poll() is not None:
                    return
                time.sleep(0.01)

    def output_encoding(self) -> str:
        return "utf-8"

    def command_environment(self) -> dict[str, str]:
        env = dict(self.env)
        env["LC_ALL"] = "C"  # stable, locale-independent command output for parsing
        return env

    def command_recipes(self) -> dict[str, list[list[str]]]:
        return {
            "net.addresses": [["ip", "-j", "addr"], ["hostname", "-I"]],
            "system.hostname": [["hostname"]],
        }

    # ------------------------------------------------------------------ applications
    def _data_dirs(self) -> list[Path]:
        home = Path(self.env.get("HOME") or Path.home())
        data_home = Path(self.env.get("XDG_DATA_HOME") or home / ".local" / "share")
        data_dirs = (self.env.get("XDG_DATA_DIRS") or "/usr/local/share:/usr/share").split(":")
        dirs = [data_home, *[Path(d) for d in data_dirs if d]]
        dirs += [
            Path("/var/lib/flatpak/exports/share"),
            data_home / "flatpak" / "exports" / "share",
            Path("/var/lib/snapd/desktop"),
        ]
        seen: set[Path] = set()
        out: list[Path] = []
        for d in dirs:
            if d not in seen:
                seen.add(d)
                out.append(d)
        return out

    def discover_applications(self) -> tuple[list[AppEntry], list[str]]:
        apps: dict[str, AppEntry] = {}
        diagnostics: list[str] = []
        by_exec_stem: set[str] = set()

        for base in self._data_dirs():
            adir = base / "applications"
            if not adir.is_dir():
                continue
            for f in sorted(adir.rglob("*.desktop")):
                try:
                    entry = parse_desktop_entry(f.read_text(encoding="utf-8", errors="replace"))
                except OSError as exc:
                    diagnostics.append(f"unreadable {f}: {exc}")
                    continue
                if not entry or entry.get("Type") != "Application":
                    continue
                if entry.get("NoDisplay", "").lower() == "true" or entry.get("Hidden", "").lower() == "true":
                    continue
                if entry.get("Terminal", "").lower() == "true":
                    continue  # needs a terminal emulator; handled in a later milestone
                argv = exec_to_argv(entry.get("Exec", ""))
                if not argv:
                    diagnostics.append(f"skipped {f.name}: unparsable Exec")
                    continue
                exe = self.resolve_executable(argv[0])
                if exe is None:
                    diagnostics.append(f"skipped {f.name}: executable not found ({argv[0]})")
                    continue
                argv[0] = str(exe)
                desk_id = f.relative_to(adir).as_posix().replace("/", "-")
                app_id = f"desktop:{desk_id}"
                if app_id in apps:
                    continue  # earlier data dir wins (XDG precedence)
                exec_stem = stem(argv[0])
                cats = entry.get("Categories", "").split(";")
                kind = classify(entry.get("Name", desk_id), exec_stem, cats)
                apps[app_id] = AppEntry(
                    id=app_id,
                    name=entry.get("Name", desk_id),
                    kind=kind,  # type: ignore[arg-type]
                    source="desktop_file",
                    exec_argv=argv,
                    process_match=sorted({exec_stem, stem(exe.name)}),
                    default_for=[m for m in entry.get("MimeType", "").split(";") if m][:8],
                    comment=entry.get("Comment"),
                )
                by_exec_stem.add(exec_stem)

        for name in PATH_SCAN_NAMES:
            if name in by_exec_stem:
                continue
            found = shutil.which(name, path=self.env.get("PATH"))
            if not found:
                continue
            display, kind = KNOWN_APPS[name]
            apps[f"path:{name}"] = AppEntry(
                id=f"path:{name}",
                name=display,
                kind=kind,  # type: ignore[arg-type]
                source="path",
                exec_argv=[found],
                process_match=[name, stem(found)],
            )
            by_exec_stem.add(name)

        ordered = sorted(apps.values(), key=lambda a: (a.name.casefold(), a.id))
        return ordered, diagnostics

    def _mimeapps_files(self) -> list[Path]:
        home = Path(self.env.get("HOME") or Path.home())
        cfg_home = Path(self.env.get("XDG_CONFIG_HOME") or home / ".config")
        cfg_dirs = (self.env.get("XDG_CONFIG_DIRS") or "/etc/xdg").split(":")
        desktop = (self.env.get("XDG_CURRENT_DESKTOP") or "").split(":")[0].lower()
        files: list[Path] = []
        for d in [cfg_home, *[Path(x) for x in cfg_dirs if x]]:
            if desktop:
                files.append(d / f"{desktop}-mimeapps.list")
            files.append(d / "mimeapps.list")
        data_home = Path(self.env.get("XDG_DATA_HOME") or home / ".local" / "share")
        files.append(data_home / "applications" / "mimeapps.list")
        return files

    def default_browser_id(self, apps: Sequence[AppEntry]) -> str | None:
        by_desktop = {a.id.split(":", 1)[1]: a.id for a in apps if a.id.startswith("desktop:")}
        for f in self._mimeapps_files():
            try:
                defaults = parse_mimeapps(f.read_text(encoding="utf-8", errors="replace"))
            except OSError:
                continue
            for mime in ("x-scheme-handler/https", "x-scheme-handler/http", "text/html"):
                for desk_id in defaults.get(mime, []):
                    if desk_id in by_desktop:
                        return by_desktop[desk_id]
        return None

    def launch_application(self, app: AppEntry, args: Sequence[str] = ()) -> LaunchResult:
        if not app.exec_argv:
            raise OsalError("invalid", f"{app.name} has no launch command")
        argv = [*app.exec_argv, *args]
        try:
            proc = subprocess.Popen(  # noqa: S603 - argv list from local inventory
                argv,
                stdin=subprocess.DEVNULL,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                start_new_session=True,
                close_fds=True,
            )
        except FileNotFoundError as exc:
            raise OsalError("not_found", f"cannot start {argv[0]}: {exc}") from exc
        except PermissionError as exc:
            raise OsalError("permission", f"cannot start {argv[0]}: {exc}") from exc
        except OSError as exc:
            raise OsalError("failed", f"cannot start {argv[0]}: {exc}") from exc
        self.reap_in_background(proc)
        return LaunchResult(pid=proc.pid, argv=argv, launched_via="exec")

    # ------------------------------------------------------------------ services
    _SERVICE_ALIASES = {
        "ssh": ["ssh", "sshd"], "sshd": ["sshd", "ssh"], "openssh": ["sshd", "ssh"],
        "docker": ["docker"], "cron": ["cron", "crond"], "crond": ["cron", "crond"],
        "apache": ["apache2", "httpd"], "apache2": ["apache2", "httpd"], "httpd": ["httpd", "apache2"],
        "mysql": ["mysql", "mysqld", "mariadb"], "postgres": ["postgresql"], "postgresql": ["postgresql"],
        "network": ["NetworkManager", "systemd-networkd"], "networkmanager": ["NetworkManager"],
    }
    # process names that indicate a daemon is running when no service manager is available
    _PROCESS_NAMES = {"ssh": ["sshd"], "sshd": ["sshd"], "openssh": ["sshd"], "docker": ["dockerd"],
                      "cron": ["cron", "crond"], "nginx": ["nginx"], "apache2": ["apache2", "httpd"]}

    def service_aliases(self, name: str) -> list[str]:
        key = name.strip().lower().removesuffix(".service")
        return list(dict.fromkeys(self._SERVICE_ALIASES.get(key, [key])))

    def _systemctl_show(self, systemctl: Path, unit: str) -> dict[str, str] | None:
        try:
            res = self.run_process(
                [str(systemctl), "show", f"{unit}.service", "--no-pager",
                 "-p", "LoadState", "-p", "ActiveState", "-p", "SubState", "-p", "UnitFileState",
                 "-p", "MainPID"],
                cwd=Path("/"), env=self.command_environment(), timeout_s=5, cancel=CancelToken(),
            )
        except OsalError:
            return None
        if res.exit_code != 0 or res.timed_out:
            return None
        return systemd.parse_show(res.stdout)

    def service_state(self, name: str) -> ServiceState:
        candidates = self.service_aliases(name)
        systemctl = self.resolve_system_executable("systemctl")
        manager_answered = False
        if systemctl is not None:
            for unit in candidates:
                raw = self._systemctl_show(systemctl, unit)
                if raw is None:
                    continue
                manager_answered = True
                state, enabled, detail = systemd.map_state(raw)
                if state == "not_found":
                    continue
                ports: list[int] = []
                with contextlib.suppress(ValueError):
                    main_pid = int(raw.get("MainPID", "0") or 0)
                    if state == "running" and main_pid > 0:
                        ports = self.listening_ports_for_pids([main_pid])
                return ServiceState(name=name, resolved_name=unit, state=state, enabled=enabled,  # type: ignore[arg-type]
                                    method="systemctl", raw=raw, listening_ports=ports, detail=detail)
            if manager_answered:
                return ServiceState(name=name, state="not_found", method="systemctl",
                                    detail=f"no unit found for any of: {', '.join(candidates)}")
        # No usable service manager (container, WSL1, non-systemd init): fall back to a process scan.
        procs = self._PROCESS_NAMES.get(name.strip().lower(), [])
        found = self.find_processes(procs) if procs else []
        if found:
            pids = [m.pid for m in found]
            return ServiceState(
                name=name, resolved_name=found[0].name, state="running", enabled=None, method="process_scan",
                detail="no service manager answered; inferred from a running process (enablement unknown)",
                raw={"pids": pids}, listening_ports=self.listening_ports_for_pids(pids))
        return ServiceState(
            name=name, state="unknown", method="none",
            detail=("no service manager answered and no matching process is running; "
                    "cannot tell whether the service is installed"))

    # ------------------------------------------------------------------ local IPC
    def ipc_endpoint(self, run_dir: Path, discriminator: str) -> IpcEndpoint:
        path = str(run_dir / "jarvisd.sock")
        if len(path.encode()) > 100:  # sun_path limit is ~108 bytes
            raise OsalError("invalid", f"unix socket path too long ({len(path)} chars): {path}")
        return IpcEndpoint(family="AF_UNIX", address=path, cleanup_path=path)

    def create_ipc_listener(self, endpoint: IpcEndpoint, backlog: int = 8) -> IpcListener:
        from multiprocessing.connection import Listener

        old = os.umask(0o177)  # socket is born 0600 (no window between bind() and chmod())
        try:
            listener = Listener(endpoint.address, family="AF_UNIX", backlog=backlog)  # no authkey: handshake is ours
        finally:
            os.umask(old)
        with contextlib.suppress(OSError):
            os.chmod(endpoint.address, 0o600)
        return listener

    def restrict_to_current_user(self, path: Path, *, directory: bool = False) -> bool:
        try:
            os.chmod(path, 0o700 if directory else 0o600)
        except OSError as exc:
            raise OsalError("permission", f"cannot restrict {path}: {exc}") from exc
        return True

    def peer_is_current_user(self, fd: int) -> bool | None:
        if sys.platform == "win32":  # never true at runtime (LinuxAdapter is only created on Linux); narrows type-checking
            raise OsalUnavailable("LinuxAdapter uses POSIX-only APIs")  # of this POSIX-only body when mypy targets win32
        try:
            sock = socket.fromfd(fd, socket.AF_UNIX, socket.SOCK_STREAM)
        except OSError:
            return None
        try:
            _pid, uid, _gid = struct.unpack("3i", sock.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED,
                                                                    struct.calcsize("3i")))
        except (OSError, AttributeError):
            return None
        finally:
            sock.close()
        return uid == os.geteuid()
