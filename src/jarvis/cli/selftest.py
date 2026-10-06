"""--self-test: exercise the REAL pipeline on this machine in an isolated data directory."""

from __future__ import annotations

import shutil
import time
from collections.abc import Callable
from dataclasses import dataclass

from jarvis.config.schema import JarvisConfig, ModelsConfig, OllamaConfig
from jarvis.core.approvals import StaticProvider
from jarvis.core.models import Outcome, Step
from jarvis.core.runtime import Runtime, temp_home
from jarvis.security.audit import AuditLog


@dataclass
class Check:
    name: str
    status: str  # PASS | FAIL | SKIP
    detail: str = ""


def _closed_port() -> int:
    import socket

    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    port = s.getsockname()[1]
    s.close()
    return port


def run_self_test() -> int:
    home = temp_home()
    checks: list[Check] = []

    def check(name: str, fn: Callable[[], str | None]) -> None:
        try:
            detail = fn()
            if detail and detail.startswith("SKIP:"):
                checks.append(Check(name, "SKIP", detail[5:].strip()))
            else:
                checks.append(Check(name, "PASS", detail or ""))
        except AssertionError as exc:
            checks.append(Check(name, "FAIL", str(exc) or "assertion failed"))
        except Exception as exc:
            checks.append(Check(name, "FAIL", f"{type(exc).__name__}: {exc}"))

    approving = StaticProvider(approve=True)
    platform_name = "?"
    cfg = JarvisConfig(home_override=home)
    rt = Runtime.create(cfg, use_keyring=False, approvals=approving)
    platform_name = rt.osal.name
    try:
        def contracts() -> str:
            v = rt.registry.validate_all()
            assert not v, "; ".join(map(str, v))
            return f"{len(rt.registry.names())} tool manifests valid"

        def ask(text: str, want: Outcome, contains: str | None = None) -> str:
            t = rt.agent.run(text, 60)
            assert t.outcome == want, f"{text!r}: expected {want.value}, got {t.outcome and t.outcome.value}: {t.final_response}"
            if contains:
                assert contains.lower() in (t.final_response or "").lower(), f"{text!r}: missing {contains!r} in {t.final_response!r}"
            return (t.final_response or "").splitlines()[0][:80] if t.final_response else ""

        check("tool manifest contracts", contracts)
        check("hostname request", lambda: ask("what is my hostname", Outcome.VERIFIED, "hostname"))
        check("IP request (system API)", lambda: ask("get my IP", Outcome.VERIFIED, "ip address"))
        check("IP request (terminal path)", lambda: ask("get my IP using the terminal", Outcome.VERIFIED, "ip address"))
        check("RAM request", lambda: ask("how much RAM do I have", Outcome.VERIFIED, "ram"))
        check("disk + cpu + memory (parallel)", lambda: ask("check CPU, RAM, disk and network", Outcome.VERIFIED, "disk"))
        check("file listing", lambda: ask("show the files here", Outcome.VERIFIED))
        check("application discovery", lambda: ask("show installed applications", Outcome.VERIFIED))
        check("read-only terminal command", lambda: ask(
            "execute this read-only terminal command: hostname", Outcome.VERIFIED))
        check("ambiguous 'open' asks, runs nothing", lambda: ask("open", Outcome.NEEDS_INPUT, "what would you like"))
        check("destructive command is denied", lambda: ask("run command: rm -rf /", Outcome.FAILED, "denied by policy"))
        check("unknown request is not guessed", lambda: ask("tell me a joke", Outcome.UNSUPPORTED, "have not done anything"))

        def malformed() -> str:
            run = rt.executor.run_step(
                Step(id="s1", tool="terminal.execute", arguments={"argv": "hostname"}),
                task_id="selftest", results={}, cancel=__import__("jarvis.common.cancel", fromlist=["CancelToken"]).CancelToken(),
                mode=rt.config.policy.mode)
            assert run.result.failure_class and run.result.failure_class.value == "invalid_arguments", run.result.error
            return "rejected before execution"

        check("malformed arguments rejected", malformed)

        def timeout() -> str:
            if not shutil.which("sleep"):
                return "SKIP: no 'sleep' command on this platform"
            t0 = time.monotonic()
            run = rt.executor.run_step(
                Step(id="s1", tool="terminal.execute", arguments={"argv": ["sleep", "10"], "timeout_s": 0.5}),
                task_id="selftest", results={}, cancel=__import__("jarvis.common.cancel", fromlist=["CancelToken"]).CancelToken(),
                mode=rt.config.policy.mode)
            assert run.result.failure_class and run.result.failure_class.value == "timeout", run.result.error
            assert time.monotonic() - t0 < 5, "timeout was not enforced promptly"
            return f"killed after {run.result.duration_ms} ms"

        check("timeout enforced", timeout)

        def cancel() -> str:
            if not shutil.which("sleep"):
                return "SKIP: no 'sleep' command on this platform"
            h = rt.agent.submit("run command: sleep 30")
            time.sleep(0.8)
            t0 = time.monotonic()
            stop = rt.agent.run("stop", 10)
            h.wait(5)
            assert h.task.outcome == Outcome.CANCELLED, f"task outcome {h.task.outcome}"
            assert time.monotonic() - t0 < 4, "cancellation took too long"
            assert "Stopped" in (stop.final_response or ""), stop.final_response
            return f"cancelled in {time.monotonic() - t0:.2f}s"

        check("cancellation kills a running command", cancel)

        def backend_down() -> str:
            cfg2 = JarvisConfig(
                home_override=temp_home(),
                models=ModelsConfig(
                    default_backend="ollama", fallback_order=["native"],
                    ollama=OllamaConfig(enabled=True, model="none", base_url=f"http://127.0.0.1:{_closed_port()}",
                                        health_timeout_s=1.0)),
            )
            rt2 = Runtime.create(cfg2, use_keyring=False)
            try:
                rep = rt2.gateway.health("ollama", force=True)
                assert rep.server_reachable is False, rep
                t = rt2.agent.run("what is my hostname", 30)
                assert t.outcome == Outcome.VERIFIED, t.final_response
                return f"ollama {rep.level}; native brain still answered"
            finally:
                rt2.close()

        check("model backend down: runtime keeps working", backend_down)

        def daemon_roundtrip() -> str:
            import threading

            from jarvis.daemon.server import Daemon
            from jarvis.ipc.client import DaemonUnavailable, IpcClient

            d = Daemon.create(JarvisConfig(home_override=temp_home()), use_keyring=False)
            th = threading.Thread(target=d.serve_forever, daemon=True)
            th.start()
            try:
                client = None
                for _ in range(100):
                    try:
                        client = IpcClient(d.endpoint, d.run_dir)
                        break
                    except DaemonUnavailable:
                        time.sleep(0.05)
                assert client is not None, "daemon did not accept connections"
                with client:
                    r = client.ask("what is my hostname")
                    assert r.outcome == "VERIFIED", r.text
                    denied = client.ask("run command: rm -rf /")
                    assert denied.outcome == "FAILED" and "denied by policy" in denied.text, denied.text
                return f"IPC {d.endpoint.family}: request verified, destructive command denied"
            finally:
                d.stop()
                th.join(10)

        check("daemon + IPC round trip", daemon_roundtrip)

        def query_index() -> str:
            names = [t.manifest.name for t in rt.registry.query("what is my ip address", rt.osal.name)]
            assert names and names[0] == "net.get_addresses", names
            return f"query('ip address') -> {names[0]}"

        check("registry capability query", query_index)

        def audit_ok() -> str:
            rep = rt.audit.verify()
            assert rep.ok, f"broken at seq {rep.first_bad_seq}: {rep.reason}"
            return f"{rep.entries} entries, hash chain intact"

        check("audit hash chain", audit_ok)

        def audit_reopen() -> str:
            again = AuditLog(rt.dirs.db / "audit.db")
            try:
                assert again.verify().ok
            finally:
                again.close()
            return "reopened and verified"

        check("audit reopen", audit_reopen)
    finally:
        rt.close()
        shutil.rmtree(home, ignore_errors=True)

    width = max(len(c.name) for c in checks)
    for c in checks:
        print(f"[{c.status}] {c.name.ljust(width)}  {c.detail}")
    failed = [c for c in checks if c.status == "FAIL"]
    skipped = [c for c in checks if c.status == "SKIP"]
    print(f"\n{len(checks) - len(failed) - len(skipped)} passed, {len(failed)} failed, {len(skipped)} skipped"
          f" (platform: {platform_name})")
    return 1 if failed else 0
