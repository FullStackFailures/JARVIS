"""system.* tools: platform-neutral facts, all answered through the OSAL (psutil/stdlib)."""

from __future__ import annotations

from pathlib import Path
from typing import Any

from jarvis.common.paths import resolve_path
from jarvis.core.models import FailureClass, Postcondition
from jarvis.osal.types import OsalError, dump
from jarvis.tools._manifest import build_manifest, obj
from jarvis.tools.base import Tool, ToolContext, ToolFailure, ToolOutput, Verification, failure_from_osal

_S = {"type": "string"}
_NS = {"type": ["string", "null"]}
_I = {"type": "integer"}
_NI = {"type": ["integer", "null"]}
_N = {"type": "number"}


class SystemInfo(Tool):
    manifest = build_manifest(
        "system.info",
        "OS name/version/architecture, hostname, CPU counts and load, uptime, shell, session and privilege state.",
        obj({}),
        obj(
            {
                "os": _S, "os_release": _S, "os_version": _S, "distro": _NS, "arch": _S,
                "hostname": _S, "python": _S, "cpu_logical": _NI, "cpu_physical": _NI,
                "cpu_percent": _N, "uptime_s": _N, "shell": _NS,
                "session": {"type": "object"}, "privilege": {"type": "object"},
            },
            ["os", "arch", "hostname", "cpu_logical", "cpu_percent"],
            extra=True,
        ),
        permissions=["system.read"],
        methods=["psutil", "platform"],
        postcondition=Postcondition(kind="field_present", path="data.os", description="OS reported"),
        tags=["system", "os", "cpu", "info"],
    )

    def execute(self, args: dict[str, Any], ctx: ToolContext) -> ToolOutput:
        import platform as _pf

        a = ctx.osal
        info = a.detect_os()
        cpu = a.cpu_info()
        return ToolOutput(
            {
                "os": info.system,
                "os_release": info.release,
                "os_version": info.version,
                "distro": info.distro,
                "arch": info.arch,
                "hostname": info.hostname,
                "python": _pf.python_version(),
                "cpu_logical": cpu["logical"],
                "cpu_physical": cpu["physical"],
                "cpu_percent": float(cpu["percent"]),
                "uptime_s": a.uptime_seconds(),
                "shell": a.detect_shell().default_shell,
                "session": dump(a.detect_session()),
                "privilege": dump(a.privilege_state()),
            },
            method="psutil",
        )


class SystemHostname(Tool):
    manifest = build_manifest(
        "system.hostname",
        "The machine's hostname and fully-qualified name.",
        obj({}),
        obj({"hostname": _S, "fqdn": _S}, ["hostname", "fqdn"]),
        permissions=["system.read"],
        methods=["socket"],
        postcondition=Postcondition(kind="truthy", path="data.hostname"),
        tags=["system", "hostname", "name"],
    )

    def execute(self, args: dict[str, Any], ctx: ToolContext) -> ToolOutput:
        return ToolOutput(ctx.osal.hostname(), method="socket")


class SystemMemory(Tool):
    manifest = build_manifest(
        "system.memory",
        "Physical RAM and swap totals and usage in bytes.",
        obj({}),
        obj(
            {"total": _I, "available": _I, "used": _I, "percent": _N, "swap_total": _I, "swap_used": _I},
            ["total", "available", "used", "percent"],
        ),
        permissions=["system.read"],
        methods=["psutil"],
        postcondition=Postcondition(kind="truthy", path="data.total"),
        tags=["system", "memory", "ram"],
    )

    def execute(self, args: dict[str, Any], ctx: ToolContext) -> ToolOutput:
        return ToolOutput(dump(ctx.osal.memory()), method="psutil")


class SystemDisk(Tool):
    manifest = build_manifest(
        "system.disk",
        "Disk usage for a path (default: the working directory) and optionally all mounted partitions.",
        obj(
            {
                "path": {"type": "string", "minLength": 1},
                "all": {"type": "boolean"},
            }
        ),
        obj(
            {
                "path": _S, "total": _I, "used": _I, "free": _I, "percent": _N,
                "partitions": {"type": "array", "items": {"type": "object"}},
            },
            ["path", "total", "used", "free", "percent"],
        ),
        permissions=["system.read", "fs.read"],
        methods=["psutil"],
        postcondition=Postcondition(kind="truthy", path="data.total"),
        tags=["system", "disk", "storage"],
    )

    def execute(self, args: dict[str, Any], ctx: ToolContext) -> ToolOutput:
        target: Path = resolve_path(args["path"], ctx.cwd) if "path" in args else ctx.cwd
        try:
            data = dump(ctx.osal.disk_usage(target))
            if args.get("all"):
                data["partitions"] = [dump(p) for p in ctx.osal.partitions()]
        except OsalError as exc:
            raise failure_from_osal(exc) from exc
        if data["total"] <= 0:
            raise ToolFailure(FailureClass.TOOL_ERROR, f"disk reported zero capacity for {target}")
        return ToolOutput(data, method="psutil")


class SystemServiceStatus(Tool):
    manifest = build_manifest(
        "system.service_status",
        "State of an operating-system service (running/stopped/failed/not_found/unknown) via the native "
        "service manager, with enablement and listening ports when known.",
        obj({"name": {"type": "string", "minLength": 1, "maxLength": 100,
                      "pattern": r"^[A-Za-z0-9_.@ \-]+$"}}, ["name"]),
        obj(
            {
                "name": _S, "resolved_name": _NS,
                "state": {"enum": ["running", "stopped", "failed", "not_found", "unknown"]},
                "enabled": {"type": ["boolean", "null"]}, "method": _S, "detail": _NS,
                "raw": {"type": "object"}, "listening_ports": {"type": "array", "items": _I},
            },
            ["name", "state", "method"],
        ),
        permissions=["system.read", "proc.read"],
        methods=["systemctl", "process_scan", "scm"],
        postcondition=Postcondition(kind="tool_verified",
                                    description="the service manager gave a definite state (not 'unknown')"),
        tags=["system", "service", "daemon", "ssh", "status"],
        examples=[{"name": "ssh"}],
    )

    def execute(self, args: dict[str, Any], ctx: ToolContext) -> ToolOutput:
        try:
            state = ctx.osal.service_state(str(args["name"]))
        except OsalError as exc:
            raise failure_from_osal(exc) from exc
        return ToolOutput(dump(state), method=state.method)

    def verify(self, args: dict[str, Any], output: ToolOutput, ctx: ToolContext) -> Verification | None:
        st = output.data.get("state")
        if st == "unknown":
            return Verification(False, f"state of {args['name']!r} is unknown: {output.data.get('detail')}")
        return Verification(True, f"service manager reported {st}")


TOOLS = [SystemInfo, SystemHostname, SystemMemory, SystemDisk, SystemServiceStatus]
