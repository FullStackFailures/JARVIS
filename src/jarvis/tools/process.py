"""process.* tools (read-only)."""

from __future__ import annotations

from typing import Any

from jarvis.core.models import Postcondition
from jarvis.osal.types import OsalError, dump
from jarvis.tools._manifest import build_manifest, obj
from jarvis.tools.base import Tool, ToolContext, ToolOutput, failure_from_osal


class ProcessList(Tool):
    manifest = build_manifest(
        "process.list",
        "List running processes (name, pid, user, memory), sorted by memory, cpu or name; optional name filter.",
        obj(
            {
                "limit": {"type": "integer", "minimum": 1, "maximum": 500},
                "sort_by": {"enum": ["memory", "cpu", "name"]},
                "name_filter": {"type": "string", "minLength": 1, "maxLength": 100},
            }
        ),
        obj(
            {
                "processes": {"type": "array", "items": {"type": "object"}},
                "total": {"type": "integer"},
                "truncated": {"type": "boolean"},
                "own_pid_included": {"type": "boolean"},
            },
            ["processes", "total", "truncated"],
        ),
        permissions=["proc.read"],
        methods=["psutil"],
        postcondition=Postcondition(kind="min_items", path="data.processes", value=1,
                                    description="at least one process was listed"),
        tags=["process", "processes", "list", "cpu", "memory"],
        examples=[{"limit": 10, "sort_by": "memory"}],
    )

    def execute(self, args: dict[str, Any], ctx: ToolContext) -> ToolOutput:
        try:
            res = ctx.osal.list_processes(limit=int(args.get("limit", 25)),
                                          sort_by=str(args.get("sort_by", "memory")),
                                          name_filter=args.get("name_filter"))
        except OsalError as exc:
            raise failure_from_osal(exc) from exc
        return ToolOutput(dump(res), method="psutil")


TOOLS = [ProcessList]
