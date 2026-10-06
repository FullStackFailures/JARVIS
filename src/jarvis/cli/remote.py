"""CLI -> jarvisd client commands (``ask``, ``daemon status|stop``, ``audit verify``).

The CLI never executes tools itself on this path: it ships the text to the daemon, answers
approval prompts on the user's TTY, and prints the daemon's result. Approval is fail-closed:
no TTY and no ``--yes`` => every prompt is declined. ``--yes`` can only answer ASK prompts;
DENY never reaches the client, so it cannot be bypassed from here.
"""

from __future__ import annotations

import hashlib
import json
import sys
from pathlib import Path

from jarvis.config.paths import resolve_dirs
from jarvis.config.schema import JarvisConfig
from jarvis.ipc import protocol as P
from jarvis.ipc.client import DaemonUnavailable, IpcClient
from jarvis.osal.detect import create_adapter
from jarvis.osal.types import IpcEndpoint
from jarvis.security.redact import REDACTOR

EXIT_OK, EXIT_FAIL, EXIT_UNAVAILABLE = 0, 1, 3
OK_OUTCOMES = {"VERIFIED", "REPLY", "EXECUTED_UNVERIFIED"}


def resolve_endpoint(config: JarvisConfig) -> tuple[IpcEndpoint, Path]:
    dirs = resolve_dirs(config.home_override)
    disc = hashlib.sha1(str(dirs.run).encode()).hexdigest()[:8] if config.home_override else ""  # noqa: S324
    return create_adapter().ipc_endpoint(dirs.run, disc), dirs.run


def connect(config: JarvisConfig) -> IpcClient:
    endpoint, run_dir = resolve_endpoint(config)
    return IpcClient(endpoint, run_dir)


def _unavailable(exc: Exception) -> int:
    print(f"jarvis: {exc}. Start it with 'jarvisd' (foreground), or use 'jarvis local ...' for an in-process run.",
          file=sys.stderr)
    return EXIT_UNAVAILABLE


def tty_approver(assume_yes: bool):
    def approve(p: P.ApprovalPrompt) -> bool:
        print(f"\nApproval required [{p.risk}]: {p.tool} {json.dumps(REDACTOR.scrub(p.arguments), ensure_ascii=False)}",
              file=sys.stderr)
        for r in p.reasons:
            print(f"  - {r}", file=sys.stderr)
        if assume_yes:
            print("  --yes given: approving this prompt", file=sys.stderr)
            return True
        if not (sys.stdin and sys.stdin.isatty()):
            print("  no interactive terminal: declined (fail closed)", file=sys.stderr)
            return False
        try:
            return input("Allow? [y/N] ").strip().lower() in {"y", "yes"}
        except (EOFError, KeyboardInterrupt):
            return False

    return approve


def ask(config: JarvisConfig, text: str, *, assume_yes: bool, as_json: bool) -> int:
    try:
        client = connect(config)
    except DaemonUnavailable as exc:
        return _unavailable(exc)
    with client:
        try:
            res = client.ask(text, on_approval=tty_approver(assume_yes))
        except KeyboardInterrupt:
            print("interrupted", file=sys.stderr)
            return EXIT_FAIL
        except (RuntimeError, TimeoutError, OSError, EOFError) as exc:
            print(f"jarvis: request failed: {exc}", file=sys.stderr)
            return EXIT_FAIL
    if as_json:
        print(json.dumps(REDACTOR.scrub(res.task), indent=2, ensure_ascii=False))
    elif res.outcome == "REPLY":
        print(res.text)
    else:
        print(f"[{res.outcome or res.status.upper()}] {res.text}")
    return EXIT_OK if res.outcome in OK_OUTCOMES else EXIT_FAIL


def daemon_cmd(config: JarvisConfig, action: str) -> int:
    try:
        client = connect(config)
    except DaemonUnavailable as exc:
        if action == "status":
            print(f"jarvisd: NOT RUNNING ({exc})")
        return EXIT_UNAVAILABLE if action == "status" else EXIT_OK
    with client:
        if action == "status":
            pong = client.ping()
            st = client.status()
            print(f"jarvisd: RUNNING pid={pong.pid} version={pong.version} protocol={pong.protocol} "
                  f"mode={st.get('permission_mode')} active_tasks={st.get('active_tasks')} "
                  f"audit_entries={st.get('audit_entries')}")
            return EXIT_OK
        client.shutdown()
        print("jarvisd: shutdown requested")
        return EXIT_OK
