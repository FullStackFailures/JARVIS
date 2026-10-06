"""terminal.execute: structured argv execution (never a shell string)."""

from __future__ import annotations

from typing import Any

from jarvis.common.paths import resolve_path
from jarvis.core.models import ExecMode, FailureClass, Postcondition, RiskLevel, SideEffect
from jarvis.osal.types import OsalError
from jarvis.tools._manifest import build_manifest, obj
from jarvis.tools.base import Tool, ToolContext, ToolFailure, ToolOutput, failure_from_osal
from jarvis.tools.parsers import PARSERS


class TerminalExecute(Tool):
    manifest = build_manifest(
        "terminal.execute",
        "Run one program with an argument vector (no shell interpretation) and return stdout, stderr, "
        "exit code, duration and platform. Subject to the command policy.",
        obj(
            {
                "argv": {
                    "type": "array",
                    "items": {"type": "string", "maxLength": 4096},
                    "minItems": 1,
                    "maxItems": 64,
                },
                "cwd": {"type": "string", "minLength": 1},
                "timeout_s": {"type": "number", "minimum": 0.1, "maximum": 120},
                "parse_as": {"enum": [*PARSERS.keys(), None]},
                "max_output_bytes": {"type": "integer", "minimum": 1024, "maximum": 1_048_576},
            },
            ["argv"],
        ),
        obj(
            {
                "command": {"type": "string"},
                "arguments": {"type": "array", "items": {"type": "string"}},
                "argv": {"type": "array", "items": {"type": "string"}},
                "cwd": {"type": "string"},
                "stdout": {"type": "string"},
                "stderr": {"type": "string"},
                "exit_code": {"type": "integer"},
                "duration_ms": {"type": "integer"},
                "platform": {"type": "string"},
                "truncated": {"type": "boolean"},
                "resolved_path": {"type": ["string", "null"]},
                "parsed": {"type": ["object", "null"]},
            },
            ["command", "arguments", "argv", "cwd", "stdout", "stderr", "exit_code",
             "duration_ms", "platform", "truncated"],
        ),
        risk=RiskLevel.MEDIUM,
        permissions=["proc.exec_readonly", "proc.exec"],
        side_effects=[SideEffect.PROCESS],
        idempotent=False,
        timeout_ms=130_000,
        cancellable=True,
        methods=["subprocess-argv"],
        resources=[],
        modes=[ExecMode.BACKGROUND],
        postcondition=Postcondition(
            kind="equals", path="data.exit_code", value=0, description="command exited with status 0"
        ),
        tags=["terminal", "command", "shell", "execute"],
        examples=[{"argv": ["hostname"]}],
    )

    def effective_timeout_ms(self, args: dict[str, Any]) -> int:
        return int(float(args.get("timeout_s", 15)) * 1000) + 3000

    def execute(self, args: dict[str, Any], ctx: ToolContext) -> ToolOutput:
        argv: list[str] = list(args["argv"])
        cwd = resolve_path(args["cwd"], ctx.cwd) if "cwd" in args else ctx.cwd
        if not cwd.is_dir():
            raise ToolFailure(FailureClass.NOT_FOUND, f"working directory does not exist: {cwd}")

        resolved = ctx.osal.resolve_system_executable(argv[0]) or ctx.osal.resolve_executable(argv[0])
        if resolved is None:
            raise ToolFailure(FailureClass.NOT_FOUND, f"command not found: {argv[0]}")
        exec_argv = [str(resolved), *argv[1:]]

        try:
            res = ctx.osal.run_process(
                exec_argv,
                cwd=cwd,
                env=ctx.osal.command_environment(),
                timeout_s=float(args.get("timeout_s", 15)),
                cancel=ctx.cancel,
                max_output_bytes=int(args.get("max_output_bytes", 65536)),
            )
        except OsalError as exc:
            raise failure_from_osal(exc) from exc

        data: dict[str, Any] = {
            "command": argv[0],
            "arguments": argv[1:],
            "argv": argv,
            "cwd": str(cwd),
            "stdout": res.stdout,
            "stderr": res.stderr,
            "exit_code": res.exit_code if res.exit_code is not None else -1,
            "duration_ms": res.duration_ms,
            "platform": ctx.osal.name,
            "truncated": res.truncated,
            "resolved_path": str(resolved),
            "parsed": None,
        }
        if res.cancelled:
            raise ToolFailure(FailureClass.CANCELLED, "command was cancelled", data=data)
        if res.timed_out:
            raise ToolFailure(
                FailureClass.TIMEOUT,
                f"command exceeded its {args.get('timeout_s', 15)}s timeout and was killed",
                data=data,
            )
        if res.exit_code != 0:
            first = (res.stderr.strip().splitlines() or [""])[0][:200]
            raise ToolFailure(
                FailureClass.COMMAND_FAILED,
                f"{argv[0]} exited with status {res.exit_code}" + (f": {first}" if first else ""),
                data=data,
            )
        if args.get("parse_as"):
            data["parsed"] = PARSERS[args["parse_as"]](argv, res.stdout)
        return ToolOutput(data, method="subprocess-argv")


TOOLS = [TerminalExecute]
