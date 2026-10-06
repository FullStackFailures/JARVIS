"""Diagnostic subcommands: --doctor, --status, --tools, --tasks, --logs, --audit-verify."""

from __future__ import annotations

import importlib.metadata as md
import os
import platform as _pf
import sys

from jarvis import __version__
from jarvis.core.runtime import Runtime


def _row(*cols: str, widths: tuple[int, ...]) -> str:
    return "  " + "  ".join(c.ljust(w) for c, w in zip(cols, widths, strict=False)).rstrip()


def doctor(rt: Runtime) -> int:
    inv = rt.inventory
    print(f"JARVIS {__version__} doctor")
    print("\n== Platform ==")
    print(f"  OS            : {inv.os.system} ({inv.os.distro or inv.os.release}), version {inv.os.version[:60]}")
    print(f"  Architecture  : {inv.os.arch}    Python {_pf.python_version()}")
    print(f"  Shell         : {inv.shell.default_shell or 'unknown'} (found: {', '.join(inv.shell.available) or 'none'})")
    s = inv.session
    print(f"  Session       : type={s.session_type} desktop={s.desktop} graphical={s.graphical} init={s.init_system}")
    p = inv.privilege
    print(f"  Privilege     : user={p.user} elevated={p.is_elevated} ({p.method}); broker={p.broker}"
          f" ({p.broker_reason})")
    print(f"  Permission    : {rt.config.policy.mode.value}")
    print(f"  Working dir   : {rt.cwd}")

    print("\n== Capability inventory ==")
    w = (24, 12, 12)
    print(_row("capability", "status", "implemented", widths=w) + "  reason")
    for name, c in sorted(inv.capabilities.items()):
        print(_row(name, c.status.value, str(c.implemented), widths=w) + (f"  {c.reason}" if c.reason else ""))
    print(f"  applications discovered: {inv.apps_found}; browsers: {', '.join(inv.browsers_found) or 'none'}")

    print("\n== Intelligence backends ==")
    for bid, rep in rt.gateway.health_all(deep=False).items():
        print(f"  {bid:7} {rep.level:28} server={rep.server_reachable} model={rep.model_present} "
              f"generation={rep.generation_ok}" + (f"  - {rep.detail}" if rep.detail else ""))
    print("  display:")
    for line in rt.gateway.status_lines():
        print("    " + line)

    print("\n== Tools ==")
    for t in rt.registry.all():
        av = rt.registry.availability(t.manifest.name, rt.osal.name, inv)
        print(_row(t.manifest.name, t.manifest.risk.value, "available" if av.available else f"UNAVAILABLE: {av.reason}",
                   widths=(20, 7, 12)))
    violations = rt.registry.validate_all()
    print(f"  manifest contract violations: {len(violations)}")

    print("\n== Storage ==")
    for label, path in (("config", rt.dirs.config), ("data/db", rt.dirs.db), ("logs", rt.dirs.logs),
                        ("cache", rt.dirs.cache)):
        ok = path.is_dir() and os.access(path, os.W_OK)
        print(f"  {label:8}: {path}  [{'writable' if ok else 'NOT WRITABLE'}]")
    chain = rt.audit.verify()
    print(f"  audit chain: {'OK' if chain.ok else 'BROKEN at seq ' + str(chain.first_bad_seq)} ({chain.entries} entries)")

    print("\n== Dependencies ==")
    for pkg in ("pydantic", "jsonschema", "psutil", "platformdirs"):
        try:
            print(f"  {pkg:13}: {md.version(pkg)}")
        except md.PackageNotFoundError:
            print(f"  {pkg:13}: NOT INSTALLED")

    print("\n== Verification status ==")
    print(f"  Running on {rt.osal.name}. Platform adapters are verified only on the platform they run on;")
    print("  see docs/PLATFORM_SUPPORT.md for the implemented/tested matrix. Run --self-test to exercise this host.")
    return 0 if not violations and chain.ok else 1


def status(rt: Runtime, config: object | None = None) -> int:
    print(f"JARVIS {__version__}")
    daemon_line = "jarvisd: NOT RUNNING (figures below are a LOCAL snapshot of this CLI process, not the daemon)"
    if config is not None:
        from jarvis.cli import remote
        from jarvis.ipc.client import DaemonUnavailable

        try:
            with remote.connect(config) as c:  # type: ignore[arg-type]
                st = c.status()
                daemon_line = (f"jarvisd: RUNNING pid={c.ping().pid} active_tasks={st.get('active_tasks')} "
                               f"sessions={st.get('sessions')} (task/audit counts below come from the daemon)")
                print(daemon_line)
                for line in rt.gateway.status_lines():
                    print(line)
                print(f"Permission mode : {st.get('permission_mode')}  (elevated process: {st.get('elevated_process')})")
                print(f"Platform        : {st.get('platform')}")
                print(f"Tools           : {st.get('tools')} registered")
                print(f"Active tasks    : {st.get('active_tasks')}")
                print(f"Audit entries   : {st.get('audit_entries')}")
                return 0
        except (DaemonUnavailable, OSError, RuntimeError, TimeoutError):
            pass
    print(daemon_line)
    for line in rt.gateway.status_lines():
        print(line)
    print(f"Permission mode : {rt.config.policy.mode.value}  (elevated process: {rt.inventory.privilege.is_elevated})")
    print(f"Platform        : {rt.osal.name}")
    print(f"Tools           : {len(rt.registry.names())} registered")
    print(f"Active tasks    : {len(rt.tasks.active())}")
    print(f"Audit entries   : {rt.audit.count()}")
    return 0


def tools(rt: Runtime) -> int:
    w = (20, 7, 9, 11, 30)
    print(_row("tool", "risk", "timeout", "cancellable", "permissions", widths=w) + "  platforms / availability")
    for t in rt.registry.all():
        m = t.manifest
        av = rt.registry.availability(m.name, rt.osal.name, rt.inventory)
        print(_row(m.name, m.risk.value, f"{m.timeout_ms // 1000}s", str(m.cancellable), ",".join(m.permissions),
                   widths=w) + f"  {','.join(m.platforms)} / {'available' if av.available else 'UNAVAILABLE: ' + str(av.reason)}")
    return 0


def tasks(rt: Runtime) -> int:
    rows = rt.tasks.recent(20)
    if not rows:
        print("No tasks recorded yet.")
        return 0
    for r in rows:
        print(f"{r['created_at']}  {r['id']}  {(r['outcome'] or r['status']):24}  {r['goal'][:70]}")
    return 0


def logs(rt: Runtime, n: int) -> int:
    for e in rt.audit.tail(n):
        brief = ""
        p = e.payload
        for key in ("tool", "request", "decision", "outcome", "note"):
            if key in p:
                brief += f" {key}={str(p[key])[:60]}"
        print(f"{e.seq:5} {e.ts} {e.kind:18} {e.task_id or '-':18}{brief}")
    return 0


def audit_verify(rt: Runtime) -> int:
    rep = rt.audit.verify()
    if rep.ok:
        print(f"audit chain OK ({rep.entries} entries)")
        return 0
    print(f"audit chain BROKEN at seq {rep.first_bad_seq}: {rep.reason}", file=sys.stderr)
    return 1
