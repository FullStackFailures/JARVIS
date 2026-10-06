"""``python -m jarvis`` entry point: text mode over the same Agent API future voice will use."""

from __future__ import annotations

import argparse
import json
import sys
from collections.abc import Sequence

from jarvis import __version__
from jarvis.config import ConfigError, load_config
from jarvis.config.paths import resolve_dirs
from jarvis.core.approvals import DenyAllProvider, InteractiveProvider
from jarvis.core.models import Outcome, PermissionMode, Task
from jarvis.core.runtime import Runtime
from jarvis.security.logsetup import setup_logging
from jarvis.security.redact import REDACTOR

EXIT_OK, EXIT_FAIL, EXIT_USAGE = 0, 1, 2


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="jarvis", description="JARVIS - AI computer assistant (Milestone 1: kernel)")
    p.add_argument("request", nargs="*", help=(
        "'ask <text>' sends a request to jarvisd; 'daemon status|stop'; 'audit verify'; "
        "'local <text>' or bare text runs IN-PROCESS (no daemon); omit for the local REPL"))
    p.add_argument("--yes", action="store_true", help="auto-approve ASK prompts for 'ask' (DENY is never bypassed)")
    p.add_argument("--version", action="store_true", help="print the version")
    p.add_argument("--doctor", action="store_true", help="show platform, capability, backend and tool diagnostics")
    p.add_argument("--self-test", action="store_true", help="exercise the real pipeline on this machine")
    p.add_argument("--status", action="store_true", help="show active intelligence sources and runtime status")
    p.add_argument("--tools", action="store_true", help="list registered tools and their availability")
    p.add_argument("--tasks", action="store_true", help="show recent task history")
    p.add_argument("--logs", nargs="?", const=20, type=int, metavar="N", help="show the last N audit entries")
    p.add_argument("--audit-verify", action="store_true", help="verify the audit log hash chain")
    p.add_argument("--mode", choices=[m.value.lower() for m in PermissionMode], help="permission mode override")
    p.add_argument("--home", help="use this directory for ALL config/data/logs (portable/test installs)")
    p.add_argument("--json", action="store_true", help="print the full structured task record as JSON")
    return p


def format_task(task: Task, as_json: bool) -> str:
    if as_json:
        return json.dumps(REDACTOR.scrub(task.model_dump(mode="json")), indent=2, ensure_ascii=False)
    word = task.outcome.value if task.outcome else task.status.value.upper()
    text = task.final_response or ""
    if task.outcome == Outcome.REPLY:
        return text
    return f"[{word}] {text}"


def main(argv: Sequence[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    if args.version:
        print(f"jarvis {__version__}")
        return EXIT_OK

    env_overrides = None
    if args.home:
        import os

        env_overrides = {**os.environ, "JARVIS_HOME": args.home}
    try:
        config, dotenv = load_config(env=env_overrides)
    except ConfigError as exc:
        print(f"configuration error: {exc}", file=sys.stderr)
        return EXIT_USAGE
    if args.mode:
        config = config.model_copy(update={"policy": config.policy.model_copy(
            update={"mode": PermissionMode(args.mode.upper())})})

    dirs = resolve_dirs(config.home_override)
    dirs.ensure()
    setup_logging(config.logging.level, str(dirs.logs), config.logging.log_to_file)

    from jarvis.cli import commands

    if args.self_test:
        from jarvis.cli.selftest import run_self_test

        return run_self_test()

    words: list[str] = list(args.request)
    if words and words[0] == "ask" and len(words) > 1:
        from jarvis.cli import remote

        return remote.ask(config, " ".join(words[1:]), assume_yes=args.yes, as_json=args.json)
    if words[:1] == ["daemon"] and len(words) == 2 and words[1] in {"status", "stop"}:
        from jarvis.cli import remote

        return remote.daemon_cmd(config, words[1])
    if words[:2] == ["audit", "verify"] and len(words) == 2:
        args.audit_verify = True
        words = []
    elif words[:1] == ["local"]:
        words = words[1:]
    args.request = words

    interactive = bool(sys.stdin and sys.stdin.isatty())
    runtime = Runtime.create(
        config, dotenv=dotenv, env=env_overrides,
        approvals=InteractiveProvider() if interactive and not args.json else DenyAllProvider(),
    )
    try:
        if args.doctor:
            return commands.doctor(runtime)
        if args.status:
            return commands.status(runtime, config)
        if args.tools:
            return commands.tools(runtime)
        if args.tasks:
            return commands.tasks(runtime)
        if args.logs is not None:
            return commands.logs(runtime, args.logs)
        if args.audit_verify:
            return commands.audit_verify(runtime)
        if args.request:
            task = runtime.agent.run(" ".join(args.request), timeout=300)
            print(format_task(task, args.json))
            return EXIT_OK if task.outcome in {Outcome.VERIFIED, Outcome.REPLY, Outcome.EXECUTED_UNVERIFIED} else EXIT_FAIL
        return repl(runtime, args.json)
    finally:
        runtime.close()


def repl(runtime: Runtime, as_json: bool) -> int:
    interactive = bool(sys.stdin and sys.stdin.isatty())
    if interactive:
        print(f"JARVIS {__version__} - type a request, or 'exit'. Ctrl-C cancels the running task.")
        for line in runtime.gateway.status_lines():
            print("  " + line)
    while True:
        try:
            line = input("jarvis> " if interactive else "")
        except EOFError:
            return EXIT_OK
        except KeyboardInterrupt:
            print()
            continue
        line = line.strip()
        if not line:
            continue
        if line.lower() in {"exit", "quit", "bye"}:
            return EXIT_OK
        handle = runtime.agent.submit(line)
        try:
            while not handle.done:
                handle.wait(0.2)
        except KeyboardInterrupt:
            runtime.agent.cancel_all("interrupted from the keyboard")
            handle.wait(5)
        print(format_task(handle.task, as_json))


if __name__ == "__main__":
    raise SystemExit(main())
