"""apps.* tools: discover installed applications and open them (with process verification)."""

from __future__ import annotations

import time
from typing import Any

from jarvis.core.models import (
    EntityHint,
    ExecMode,
    FailureClass,
    Postcondition,
    RiskLevel,
    SideEffect,
)
from jarvis.osal.types import AppEntry, OsalError, dump
from jarvis.tools._manifest import build_manifest, obj
from jarvis.tools.apps_matching import rank
from jarvis.tools.base import (
    Tool,
    ToolContext,
    ToolFailure,
    ToolOutput,
    Verification,
    failure_from_osal,
)

_KINDS = ["browser", "terminal", "editor", "media", "office", "file_manager", "other"]


class AppsDiscover(Tool):
    manifest = build_manifest(
        "apps.discover",
        "Discover installed applications; optionally filter by kind or name query. "
        "Reports the preferred match and whether the query is ambiguous.",
        obj(
            {
                "query": {"type": ["string", "null"]},
                "kind": {"enum": [*_KINDS, None]},
                "limit": {"type": "integer", "minimum": 1, "maximum": 500},
            }
        ),
        obj(
            {
                "apps": {"type": "array", "items": {"type": "object"}},
                "total_installed": {"type": "integer"},
                "matched": {"type": "integer"},
                "preferred_id": {"type": ["string", "null"]},
                "ambiguous": {"type": "boolean"},
                "candidate_names": {"type": "array", "items": {"type": "string"}},
                "default_browser_id": {"type": ["string", "null"]},
                "diagnostics": {"type": "array", "items": {"type": "string"}},
            },
            ["apps", "total_installed", "matched", "preferred_id", "ambiguous"],
        ),
        permissions=["apps.read"],
        methods=["desktop_files+PATH", "registry+startmenu+PATH"],
        postcondition=Postcondition(kind="field_present", path="data.apps"),
        tags=["apps", "applications", "discover", "installed", "browser"],
    )

    def execute(self, args: dict[str, Any], ctx: ToolContext) -> ToolOutput:
        try:
            apps, diagnostics = ctx.osal.discover_applications()
            default_id = ctx.osal.default_browser_id(apps)
        except OsalError as exc:
            raise failure_from_osal(exc) from exc
        result = rank(
            apps, query=args.get("query"), kind=args.get("kind"), default_browser_id=default_id
        )
        limit = int(args.get("limit", 100))
        shown = result.matches[:limit]
        data = {
            "apps": [dump(a) for a in shown],
            "total_installed": len(apps),
            "matched": len(result.matches),
            "preferred_id": result.preferred_id,
            "ambiguous": result.ambiguous,
            "candidate_names": result.candidate_names,
            "default_browser_id": default_id,
            "diagnostics": diagnostics[:10],
        }
        return ToolOutput(
            data,
            method="inventory",
            entities=[
                EntityHint(type="app_list", value=[dump(a) for a in shown],
                           label=args.get("query") or args.get("kind") or "installed applications")
            ],
        )


class AppsOpen(Tool):
    manifest = build_manifest(
        "apps.open",
        "Launch an installed application by its inventory id and verify that its process appears.",
        obj({"app_id": {"type": "string", "minLength": 1}}, ["app_id"]),
        obj(
            {
                "app_id": {"type": "string"},
                "name": {"type": "string"},
                "pid": {"type": ["integer", "null"]},
                "launched_via": {"type": "string"},
                "before_pids": {"type": "array", "items": {"type": "integer"}},
                "observed_pids": {"type": "array", "items": {"type": "integer"}},
                "verification_level": {"type": "string"},
                "window_verified": {"type": ["boolean", "null"]},
                "note": {"type": ["string", "null"]},
            },
            ["app_id", "name", "pid", "launched_via"],
        ),
        risk=RiskLevel.MEDIUM,
        permissions=["apps.launch"],
        side_effects=[SideEffect.PROCESS, SideEffect.UI_INTERACTION],
        idempotent=False,
        timeout_ms=30_000,
        cancellable=False,
        requires_capability=["apps.launch"],
        methods=["exec", "shell_appsfolder"],
        resources=["app_launch"],
        modes=[ExecMode.FOREGROUND, ExecMode.HYBRID],
        postcondition=Postcondition(
            kind="tool_verified", description="the application's process is observed running"
        ),
        tags=["apps", "open", "launch", "application"],
    )

    def execute(self, args: dict[str, Any], ctx: ToolContext) -> ToolOutput:
        if ctx.config.apps.require_graphical_session and not ctx.inventory.session.graphical:
            raise ToolFailure(
                FailureClass.UNAVAILABLE,
                "no graphical session is available (neither DISPLAY nor WAYLAND_DISPLAY is set), "
                "so a desktop application cannot be shown",
            )
        try:
            apps, _ = ctx.osal.discover_applications()
        except OsalError as exc:
            raise failure_from_osal(exc) from exc
        app: AppEntry | None = next((a for a in apps if a.id == args["app_id"]), None)
        if app is None:
            raise ToolFailure(
                FailureClass.NOT_FOUND, f"application {args['app_id']!r} is not in the inventory"
            )
        before = sorted(p.pid for p in ctx.osal.find_processes(app.process_match))
        try:
            launched = ctx.osal.launch_application(app)
        except OsalError as exc:
            raise failure_from_osal(exc) from exc
        return ToolOutput(
            {
                "app_id": app.id,
                "name": app.name,
                "pid": launched.pid,
                "launched_via": launched.launched_via,
                "before_pids": before,
                "observed_pids": [],
                "verification_level": "none",
                "window_verified": None,
                "note": launched.note,
            },
            method=launched.launched_via,
            entities=[EntityHint(type="app", value=dump(app), label=app.name)],
        )

    def verify(self, args: dict[str, Any], output: ToolOutput, ctx: ToolContext) -> Verification | None:
        d = output.data
        match_names = self._match_names(args, ctx)
        before = set(d.get("before_pids", []))
        pid = d.get("pid")
        deadline = time.monotonic() + ctx.config.apps.verify_timeout_s
        observed: set[int] = set()
        while True:
            if pid is not None and ctx.osal.pid_alive(pid):
                observed.add(pid)
            for p in ctx.osal.find_processes(match_names):
                if p.pid not in before and ctx.osal.pid_alive(p.pid):
                    observed.add(p.pid)
            if observed or time.monotonic() >= deadline or ctx.cancel.is_set():
                break
            ctx.cancel.wait(0.1)
        if observed:
            return Verification(
                True,
                f"process observed running (pid {sorted(observed)[0]}); window state not checked",
                {"observed_pids": sorted(observed), "verification_level": "process"},
            )
        if pid is None and not match_names:
            return Verification(None, "launched through the shell; process cannot be attributed")
        return Verification(
            False,
            f"launch command ran but no running process was observed within "
            f"{ctx.config.apps.verify_timeout_s:.0f}s (it may have exited immediately)",
        )

    @staticmethod
    def _match_names(args: dict[str, Any], ctx: ToolContext) -> list[str]:
        apps, _ = ctx.osal.discover_applications()
        app = next((a for a in apps if a.id == args["app_id"]), None)
        return list(app.process_match) if app else []


class AppsStatus(Tool):
    manifest = build_manifest(
        "apps.status",
        "Is an installed application running? Resolves the name through the application inventory, "
        "then checks for matching processes.",
        obj({"query": {"type": "string", "minLength": 1, "maxLength": 100}}, ["query"]),
        obj(
            {
                "query": {"type": "string"},
                "app_id": {"type": ["string", "null"]},
                "name": {"type": ["string", "null"]},
                "installed": {"type": "boolean"},
                "running": {"type": ["boolean", "null"]},
                "pids": {"type": "array", "items": {"type": "integer"}},
                "ambiguous": {"type": "boolean"},
                "candidate_names": {"type": "array", "items": {"type": "string"}},
            },
            ["query", "installed", "running", "ambiguous"],
        ),
        permissions=["apps.read", "proc.read"],
        methods=["inventory+process_scan"],
        postcondition=Postcondition(kind="field_present", path="data.running"),
        tags=["apps", "application", "status", "running"],
        examples=[{"query": "firefox"}],
    )

    def execute(self, args: dict[str, Any], ctx: ToolContext) -> ToolOutput:
        query = str(args["query"])
        try:
            apps, _ = ctx.osal.discover_applications()
            result = rank(apps, query=query, kind=None, default_browser_id=None)
        except OsalError as exc:
            raise failure_from_osal(exc) from exc
        base: dict[str, Any] = {"query": query, "app_id": None, "name": None, "installed": False, "running": None,
                "pids": [], "ambiguous": result.ambiguous, "candidate_names": result.candidate_names}
        if result.ambiguous:
            base.update(installed=True)
            return ToolOutput(base, method="inventory")
        app = next((a for a in result.matches if a.id == result.preferred_id), None)
        if app is None:
            # Not in the inventory: it may still be a running process, which we can report truthfully.
            procs = ctx.osal.find_processes([query.lower()])
            base.update(running=bool(procs), pids=[pr.pid for pr in procs])
            return ToolOutput(base, method="process_scan")
        procs = ctx.osal.find_processes(list(app.process_match)) if app.process_match else []
        running: bool | None = bool(procs) if app.process_match else None
        base.update(app_id=app.id, name=app.name, installed=True, running=running, pids=[pr.pid for pr in procs])
        return ToolOutput(base, method="inventory+process_scan")


TOOLS = [AppsDiscover, AppsOpen, AppsStatus]
