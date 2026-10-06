"""Windows OSAL adapter.

IMPORTANT: this module is imported on every platform (so it can be unit-tested for its
pure parts) but its OS calls only execute on Windows. In the Milestone 1 development
environment (Linux) the Windows-only code paths below were NOT executed; see
docs/PLATFORM_SUPPORT.md. Windows-only imports (winreg, ctypes.windll, os.startfile)
are therefore performed lazily inside methods.
"""

from __future__ import annotations

import contextlib
import getpass
import json
import os
import platform
import shutil
import subprocess
import sys
from collections.abc import Sequence
from pathlib import Path
from typing import Any, ClassVar

from jarvis.osal.base import IpcListener, OSAdapter
from jarvis.osal.common.appkinds import (
    KNOWN_APPS,
    PATH_SCAN_NAMES,
    browser_from_progid,
    classify,
    stem,
)
from jarvis.osal.types import (
    AppEntry,
    Availability,
    CapabilityEntry,
    IpcEndpoint,
    LaunchResult,
    OSInfo,
    OsalError,
    OsalUnavailable,
    PrivilegeState,
    ServiceState,
    SessionInfo,
    ShellInfo,
)

_POWERSHELL_IP_JSON = (
    "Get-NetIPAddress -AddressFamily IPv4,IPv6 | "
    "Select-Object InterfaceAlias,IPAddress,AddressFamily | ConvertTo-Json -Compress"
)


def parse_get_startapps_json(text: str) -> list[tuple[str, str]]:
    """Parse ``Get-StartApps | ConvertTo-Json`` output into (name, AppID) pairs."""
    text = text.strip()
    if not text:
        return []
    try:
        data = json.loads(text)
    except json.JSONDecodeError:
        return []
    if isinstance(data, dict):
        data = [data]
    out: list[tuple[str, str]] = []
    for item in data if isinstance(data, list) else []:
        if isinstance(item, dict) and item.get("Name") and item.get("AppID"):
            out.append((str(item["Name"]), str(item["AppID"])))
    return out


class WindowsAdapter(OSAdapter):
    name: ClassVar[str] = "windows"

    # ------------------------------------------------------------------ environment
    def _winreg(self) -> Any:
        try:
            import winreg  # type: ignore[import-not-found,unused-ignore]
        except ImportError as exc:  # not running on Windows
            raise OsalUnavailable("the Windows registry is only available on Windows") from exc
        return winreg

    def detect_os(self) -> OSInfo:
        build = None
        with contextlib.suppress(AttributeError):
            build = str(sys.getwindowsversion().build)  # type: ignore[attr-defined,unused-ignore]
        return OSInfo(
            system="windows",
            release=platform.release(),
            version=platform.version(),
            arch=platform.machine(),
            build=build,
            hostname=platform.node(),
        )

    def detect_shell(self) -> ShellInfo:
        available: dict[str, str] = {}
        for sh in ("pwsh", "powershell", "cmd"):
            found = shutil.which(sh, path=self.env.get("PATH"))
            if found:
                available[sh] = found
        return ShellInfo(default_shell=self.env.get("COMSPEC"), available=available)

    def detect_session(self) -> SessionInfo:
        name = (self.env.get("SESSIONNAME") or "").lower()
        session_type = "rdp" if name.startswith("rdp") else "console" if name else "unknown"
        return SessionInfo(
            session_type=session_type,
            desktop="windows",
            display=None,
            graphical=bool(name) and name != "services",
            init_system="scm",
        )

    def privilege_state(self) -> PrivilegeState:
        elevated = False
        method = "IsUserAnAdmin"
        try:
            import ctypes

            elevated = bool(ctypes.windll.shell32.IsUserAnAdmin())  # type: ignore[attr-defined,unused-ignore]
        except (AttributeError, OSError):
            method = "unknown (ctypes.windll unavailable)"
        try:
            user = getpass.getuser()
        except (KeyError, OSError):
            user = "unknown"
        return PrivilegeState(is_elevated=elevated, user=user, uid=None, method=method)

    def probe_capabilities(self) -> dict[str, CapabilityEntry]:
        rows = self.common_capabilities()
        sess = self.detect_session()
        rows["graphical.session"] = CapabilityEntry(
            status=Availability.AVAILABLE if sess.graphical else Availability.UNAVAILABLE,
            implemented=True,
            reason=None if sess.graphical else "no interactive desktop session detected",
        )
        rows["apps.discover"] = CapabilityEntry(status=Availability.AVAILABLE, implemented=True)
        rows["apps.launch"] = CapabilityEntry(status=Availability.AVAILABLE, implemented=True)
        return rows

    # ------------------------------------------------------------------ hooks
    def system_executable_dirs(self) -> list[Path]:
        root = Path(self.env.get("SystemRoot") or self.env.get("SYSTEMROOT") or r"C:\Windows")
        return [
            root / "System32",
            root,
            root / "System32" / "Wbem",
            root / "System32" / "WindowsPowerShell" / "v1.0",
        ]

    def executable_suffixes(self) -> list[str]:
        # .bat/.cmd are intentionally excluded: they require cmd.exe argument parsing.
        return [".exe", ".com"]

    def is_hidden(self, directory: Path, entry_name: str) -> bool:
        if entry_name.startswith("."):
            return True
        try:
            import stat

            attrs = os.stat(directory / entry_name, follow_symlinks=False).st_file_attributes  # type: ignore[attr-defined,unused-ignore]
            return bool(attrs & stat.FILE_ATTRIBUTE_HIDDEN)  # type: ignore[attr-defined,unused-ignore]
        except (OSError, AttributeError):
            return False

    def popen_kwargs(self) -> dict[str, Any]:
        flags = getattr(subprocess, "CREATE_NEW_PROCESS_GROUP", 0) | getattr(
            subprocess, "CREATE_NO_WINDOW", 0
        )
        return {"creationflags": flags}

    def kill_process_tree(self, proc: subprocess.Popen[bytes]) -> None:
        taskkill = self.resolve_system_executable("taskkill")
        if taskkill is not None:
            with contextlib.suppress(OSError, subprocess.SubprocessError):
                subprocess.run(  # noqa: S603
                    [str(taskkill), "/PID", str(proc.pid), "/T", "/F"],
                    stdin=subprocess.DEVNULL,
                    stdout=subprocess.DEVNULL,
                    stderr=subprocess.DEVNULL,
                    timeout=5,
                    creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
                )
        with contextlib.suppress(OSError):
            proc.kill()

    def output_encoding(self) -> str:
        try:
            import ctypes

            return f"cp{ctypes.windll.kernel32.GetOEMCP()}"  # type: ignore[attr-defined,unused-ignore]
        except (AttributeError, OSError):
            return "utf-8"

    def command_recipes(self) -> dict[str, list[list[str]]]:
        return {
            "net.addresses": [
                ["powershell", "-NoProfile", "-NonInteractive", "-Command", _POWERSHELL_IP_JSON],
                ["ipconfig"],
            ],
            "system.hostname": [["hostname"]],
        }

    # ------------------------------------------------------------------ applications
    def discover_applications(self) -> tuple[list[AppEntry], list[str]]:
        apps: dict[str, AppEntry] = {}
        diagnostics: list[str] = []
        seen_stems: set[str] = set()

        try:
            winreg = self._winreg()
        except OsalUnavailable as exc:
            diagnostics.append(str(exc))
            winreg = None

        if winreg is not None:
            key_path = r"SOFTWARE\Microsoft\Windows\CurrentVersion\App Paths"
            for hive in (winreg.HKEY_LOCAL_MACHINE, winreg.HKEY_CURRENT_USER):
                try:
                    with winreg.OpenKey(hive, key_path) as root:
                        count = winreg.QueryInfoKey(root)[0]
                        for i in range(count):
                            sub = winreg.EnumKey(root, i)
                            try:
                                with winreg.OpenKey(root, sub) as k:
                                    exe_path = winreg.QueryValueEx(k, "")[0]
                            except OSError:
                                continue
                            exe_path = str(exe_path).strip('"')
                            if not exe_path or not Path(exe_path).is_file():
                                continue
                            s = stem(sub)
                            if s in seen_stems:
                                continue
                            display, kind0 = KNOWN_APPS.get(s, (Path(exe_path).stem, "other"))
                            kind = kind0 if s in KNOWN_APPS else classify(display, s, None)
                            apps[f"apppath:{s}"] = AppEntry(
                                id=f"apppath:{s}",
                                name=display,
                                kind=kind,  # type: ignore[arg-type]
                                source="registry_app_paths",
                                exec_argv=[exe_path],
                                process_match=[s],
                            )
                            seen_stems.add(s)
                except OSError as exc:
                    diagnostics.append(f"App Paths read failed: {exc}")

        for name in PATH_SCAN_NAMES:
            if name in seen_stems:
                continue
            found = shutil.which(name, path=self.env.get("PATH"))
            if found:
                display, kind = KNOWN_APPS[name]
                apps[f"path:{name}"] = AppEntry(
                    id=f"path:{name}",
                    name=display,
                    kind=kind,  # type: ignore[arg-type]
                    source="path",
                    exec_argv=[found],
                    process_match=[name],
                )
                seen_stems.add(name)

        ps = self.resolve_system_executable("powershell")
        if ps is not None:
            try:
                out = subprocess.run(  # noqa: S603
                    [str(ps), "-NoProfile", "-NonInteractive", "-Command",
                     "Get-StartApps | ConvertTo-Json -Compress"],
                    stdin=subprocess.DEVNULL,
                    capture_output=True,
                    timeout=20,
                    creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
                )
                text = out.stdout.decode(self.output_encoding(), errors="replace")
                for display, app_id in parse_get_startapps_json(text):
                    key = f"startapp:{app_id}"
                    s = stem(display)
                    kind = classify(display, s, None)
                    apps.setdefault(
                        key,
                        AppEntry(
                            id=key,
                            name=display,
                            kind=kind,  # type: ignore[arg-type]
                            source="start_menu",
                            launch_uri=app_id,
                            launch_method="shell_appsfolder",
                            process_match=[s],
                        ),
                    )
            except (OSError, subprocess.SubprocessError) as exc:
                diagnostics.append(f"Get-StartApps failed: {exc}")

        ordered = sorted(apps.values(), key=lambda a: (a.name.casefold(), a.id))
        return ordered, diagnostics

    def default_browser_id(self, apps: Sequence[AppEntry]) -> str | None:
        try:
            winreg = self._winreg()
        except OsalUnavailable:
            return None
        key = r"Software\Microsoft\Windows\Shell\Associations\UrlAssociations\https\UserChoice"
        try:
            with winreg.OpenKey(winreg.HKEY_CURRENT_USER, key) as k:
                progid = winreg.QueryValueEx(k, "ProgId")[0]
        except OSError:
            return None
        wanted = browser_from_progid(str(progid))
        if wanted is None:
            return None
        for a in apps:
            if a.kind == "browser" and wanted in a.process_match:
                return a.id
        return None

    def launch_application(self, app: AppEntry, args: Sequence[str] = ()) -> LaunchResult:
        if app.launch_method == "shell_appsfolder" and app.launch_uri:
            explorer = self.resolve_system_executable("explorer")
            if explorer is None:
                raise OsalUnavailable("explorer.exe not found")
            argv = [str(explorer), f"shell:AppsFolder\\{app.launch_uri}"]
            try:
                proc = subprocess.Popen(argv, close_fds=True)  # noqa: S603
            except OSError as exc:
                raise OsalError("failed", f"cannot start {app.name}: {exc}") from exc
            self.reap_in_background(proc)
            return LaunchResult(
                pid=None,
                argv=argv,
                launched_via="shell_appsfolder",
                note="launched through the shell; the resulting process is not attributable",
            )
        if not app.exec_argv:
            raise OsalError("invalid", f"{app.name} has no launch command")
        argv = [*app.exec_argv, *args]
        flags = getattr(subprocess, "DETACHED_PROCESS", 0) | getattr(
            subprocess, "CREATE_NEW_PROCESS_GROUP", 0
        )
        try:
            proc = subprocess.Popen(  # noqa: S603
                argv,
                stdin=subprocess.DEVNULL,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                close_fds=True,
                creationflags=flags,
            )
        except FileNotFoundError as exc:
            raise OsalError("not_found", f"cannot start {argv[0]}: {exc}") from exc
        except PermissionError as exc:
            raise OsalError("permission", f"cannot start {argv[0]}: {exc}") from exc
        except OSError as exc:
            raise OsalError("failed", f"cannot start {argv[0]}: {exc}") from exc
        self.reap_in_background(proc)
        return LaunchResult(pid=proc.pid, argv=argv, launched_via="exec")

    # ------------------------------------------------------------------ services (NOT VERIFIED on Windows)
    _SERVICE_ALIASES = {"ssh": ["sshd"], "sshd": ["sshd"], "openssh": ["sshd"],
                        "rdp": ["TermService"], "remote desktop": ["TermService"], "winrm": ["WinRM"],
                        "defender": ["WinDefend"], "firewall": ["mpssvc"], "docker": ["com.docker.service"]}

    def service_aliases(self, name: str) -> list[str]:
        key = name.strip().lower()
        return list(dict.fromkeys(self._SERVICE_ALIASES.get(key, [name.strip()])))

    def service_state(self, name: str) -> ServiceState:
        import psutil

        if not hasattr(psutil, "win_service_get"):
            return ServiceState(name=name, state="unknown", method="none",
                                detail="psutil Windows service API unavailable")
        candidates = self.service_aliases(name)
        for cand in candidates:
            try:
                svc = psutil.win_service_get(cand)
            except psutil.NoSuchProcess:
                continue
            except (OSError, psutil.Error) as exc:
                return ServiceState(name=name, resolved_name=cand, state="unknown", method="scm",
                                    detail=f"service control manager query failed: {exc}")
            return self._from_win_service(name, cand, svc.as_dict())
        # display-name match ("OpenSSH SSH Server")
        wanted = name.strip().lower()
        try:
            for svc in psutil.win_service_iter():
                d = svc.as_dict()
                if wanted and wanted == str(d.get("display_name", "")).lower():
                    return self._from_win_service(name, str(d.get("name")), d)
        except (OSError, psutil.Error):
            pass
        return ServiceState(name=name, state="not_found", method="scm",
                            detail=f"no Windows service matches any of: {', '.join(candidates)}")

    @staticmethod
    def _from_win_service(name: str, resolved: str, d: dict[str, Any]) -> ServiceState:
        status = str(d.get("status", "")).lower()
        state = "running" if status == "running" else "stopped" if status == "stopped" else "unknown"
        start = str(d.get("start_type", "")).lower()
        enabled = None if not start else start != "disabled"
        pid = d.get("pid")
        ports: list[int] = []
        if state == "running" and pid:
            ports = OSAdapter.listening_ports_for_pids([int(pid)])
        return ServiceState(name=name, resolved_name=resolved, state=state, enabled=enabled,  # type: ignore[arg-type]
                            method="scm", raw={k: d[k] for k in ("status", "start_type", "pid") if k in d},
                            listening_ports=ports, detail=None if state != "unknown" else f"status={status!r}")

    # ------------------------------------------------------------------ IPC (H-1 hardening; NOT VERIFIED on Windows)
    _security_api: Any = None  # injectable for tests; real ctypes facade is created lazily on first use

    def _security(self) -> Any:
        if self._security_api is None:
            from jarvis.osal.windows.winsec import WinSecurityApi

            self._security_api = WinSecurityApi()
        return self._security_api

    def ipc_endpoint(self, run_dir: Path, discriminator: str) -> IpcEndpoint:
        """Per-user pipe named by SID (not by the spoofable user name). Refuses to proceed without a SID."""
        from jarvis.osal.windows.pipe_policy import pipe_address

        return IpcEndpoint(family="AF_PIPE", address=pipe_address(self._security().current_user_sid(), discriminator),
                           cleanup_path=None)

    def create_ipc_listener(self, endpoint: IpcEndpoint, backlog: int = 8) -> IpcListener:
        from jarvis.osal.windows.pipe import SecurePipeListener
        from jarvis.osal.windows.pipe_policy import owner_only_pipe_sddl

        api = self._security()
        return SecurePipeListener(endpoint.address, owner_only_pipe_sddl(api.current_user_sid()), api)

    def peer_is_current_user(self, fd: int) -> bool | None:
        from jarvis.osal.windows.pipe import verify_peer

        api = self._security()
        try:
            return verify_peer(api, fd, api.current_user_sid())
        except OsalError:
            return None

    def restrict_to_current_user(self, path: Path, *, directory: bool = False) -> bool:
        from jarvis.osal.windows.pipe_policy import owner_only_file_sddl

        api = self._security()
        api.set_dacl_from_sddl(str(path), owner_only_file_sddl(api.current_user_sid(), directory=directory))
        return True
