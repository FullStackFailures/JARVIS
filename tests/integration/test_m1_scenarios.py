"""Required M1 scenarios against the REAL agent pipeline in-process (no daemon): real OS facts, real listener,
real subprocesses. Cross-platform tests run on both OSes; POSIX-only ones are marked and skipped with a reason."""

import os
import re
import socket
import sys
import tempfile
import threading
import time
import unittest
from pathlib import Path

import psutil

from jarvis.core.models import Outcome, StepStatus, Step
from tests.conftest_helpers import dispose, make_runtime
from tests.harness import linux_only, tags

SLEEP_CMD = "run command: ping -n 30 127.0.0.1" if sys.platform == "win32" else "run command: sleep 30"

_SUCCESS = re.compile(r"\b(done|all set|completed successfully|successfully completed|success|succeeded)\b", re.I)
_NEGATION = re.compile(r"\b(not|never|no|nothing|none|cannot|can't|couldn't|could not|didn't|did not|n't|without|unable|fail(?:ed)?)\b",
                       re.I)


def success_claims(text: str) -> list[str]:
    """Success words that are NOT in the scope of a negation/failure word earlier in the same sentence.
    "I have not done anything" is an honest negation; "Done." / "All set!" after a failure is a false claim."""
    found: list[str] = []
    for sentence in re.split(r"(?<=[.!?\n])\s+", text):
        for m in _SUCCESS.finditer(sentence):
            if not _NEGATION.search(sentence[: m.start()]):
                found.append(m.group(0))
    return found


@tags("INTEGRATION")
class Scenarios(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.dir = Path(tempfile.mkdtemp()).resolve()
        cls.rt, cls.home = make_runtime(cwd=cls.dir, approve=True)

    @classmethod
    def tearDownClass(cls):
        dispose(cls.rt, cls.home)

    def ask(self, text, timeout=60):
        return self.rt.agent.run(text, timeout=timeout)

    def test_ip_is_valid_and_belongs_to_this_host(self):
        t = self.ask("get my local IP")
        self.assertEqual(t.outcome, Outcome.VERIFIED, t.final_response)
        found = re.findall(r"\b(?:\d{1,3}\.){3}\d{1,3}\b", t.final_response)
        self.assertTrue(found, t.final_response)
        local = {a.address for addrs in psutil.net_if_addrs().values() for a in addrs}
        self.assertTrue(set(found) & local, f"{found} not among host addresses")

    def test_disk_totals_match_psutil(self):
        t = self.ask("how much disk space do I have")
        self.assertEqual(t.outcome, Outcome.VERIFIED, t.final_response)
        total = psutil.disk_usage(os.path.abspath(os.sep)).total / 1024**3
        self.assertRegex(t.final_response, r"\d")
        nums = [float(x) for x in re.findall(r"(\d+(?:\.\d+)?) GiB", t.final_response)]
        self.assertTrue(any(abs(n - total) < 0.2 * total for n in nums), (nums, total))

    def test_parallel_composite_is_faster_than_sum_of_steps(self):
        t = self.ask("check CPU, RAM, disk and network")
        self.assertEqual(t.outcome, Outcome.VERIFIED, t.final_response)
        steps = [s for s in t.step_states.values() if s.started_at and s.finished_at]
        self.assertGreaterEqual(len(steps), 3)
        total = max(s.finished_at for s in steps) - min(s.started_at for s in steps)
        summed = sum(s.finished_at - s.started_at for s in steps)
        starts = sorted(s.started_at for s in steps)
        self.assertLess(starts[-1] - starts[0], summed, "steps did not overlap")
        self.assertLessEqual(total, summed + 0.05)

    def test_every_executed_step_has_verification_and_policy(self):
        for text in ("get my local IP", "check CPU, RAM, disk and network", "what is my hostname"):
            t = self.ask(text)
            for sid, st in t.step_states.items():
                if st.result is None:
                    continue
                self.assertIsNotNone(st.policy, f"{text}: {sid} ran without a policy decision")
                if st.status == StepStatus.VERIFIED:
                    self.assertIs(st.result.verified, True, f"{text}: {sid}")
                elif st.status == StepStatus.EXECUTED:
                    self.assertIsNone(st.result.verified, f"{text}: {sid} claims executed-unverified but has a verdict")
                elif st.status == StepStatus.FAILED:
                    self.assertTrue(st.result.error is not None or st.result.verified is False, f"{text}: {sid}")

    def test_service_status_is_never_fabricated(self):
        t = self.ask("check whether SSH is running")
        self.assertIn(t.outcome, {Outcome.VERIFIED, Outcome.FAILED, Outcome.PARTIAL}, t.final_response)
        text = t.final_response.lower()
        if t.outcome == Outcome.VERIFIED:
            self.assertRegex(text, r"running|stopped|failed|not installed|not found|not_found")
        else:
            self.assertNotIn("done", text)
            self.assertRegex(text, r"unknown|could not|unable|not determine")

    def test_port_owner_finds_a_real_listener(self):
        srv = socket.socket(); srv.bind(("127.0.0.1", 0)); srv.listen(1)
        port = srv.getsockname()[1]
        try:
            t = self.ask(f"which process is using port {port}")
            self.assertEqual(t.outcome, Outcome.VERIFIED, t.final_response)
            self.assertIn(str(os.getpid()), t.final_response)
            self.assertIn(str(port), t.final_response)
        finally:
            srv.close()

    def test_free_port_reports_nothing_listening_not_a_guess(self):
        s = socket.socket(); s.bind(("127.0.0.1", 0)); port = s.getsockname()[1]; s.close()
        t = self.ask(f"what is using port {port}")
        self.assertNotIn(str(os.getpid()), t.final_response)
        self.assertRegex(t.final_response.lower(), r"no process|nothing|not (?:in use|listening)|no listener")

    def test_process_list_contains_own_pid(self):
        """The agent path lists the TOP-15 processes by memory, so on a busy host (Windows: hundreds of processes) this
        very test process is legitimately absent. What must hold: the result is honest about truncation, and when the
        list is complete it contains us. Unbounded enumeration (OSAL) must always contain us."""
        t = self.ask("list running processes")
        self.assertEqual(t.outcome, Outcome.VERIFIED, t.final_response)
        res = next(s.result for s in t.step_states.values() if s.result and s.result.data.get("processes"))
        pids = {p["pid"] for p in res.data["processes"]}
        self.assertGreaterEqual(res.data["total"], len(pids))
        self.assertEqual(res.data["truncated"], res.data["total"] > len(pids))
        self.assertEqual(res.data["own_pid_included"], os.getpid() in pids)
        if not res.data["truncated"]:
            self.assertIn(os.getpid(), pids)
        full = self.rt.osal.list_processes(limit=1_000_000, sort_by="name")
        self.assertFalse(full.truncated)
        self.assertIn(os.getpid(), {p.pid for p in full.processes})
        self.assertTrue(full.own_pid_included)

    def test_app_inventory_shape(self):
        t = self.ask("show installed applications")
        self.assertEqual(t.outcome, Outcome.VERIFIED, t.final_response)
        res = next(s.result for s in t.step_states.values() if s.result and "apps" in (s.result.data or {}))
        self.assertIsInstance(res.data["apps"], list)
        for a in res.data["apps"][:20]:
            self.assertIn("name", a)

    def test_destructive_request_is_denied_and_nothing_removed(self):
        victim = self.dir / "victim.txt"; victim.write_text("x")
        cmd = f"del {victim}" if sys.platform == "win32" else f"rm -rf {victim}"
        t = self.ask(f"run command: {cmd}")
        self.assertEqual(t.outcome, Outcome.FAILED)
        self.assertIn("denied by policy", t.final_response)
        self.assertTrue(victim.exists())

    def test_open_alone_asks_for_clarification(self):
        t = self.ask("Open.")
        self.assertEqual(t.outcome, Outcome.NEEDS_INPUT)
        self.assertFalse(t.step_states)

    def test_stop_cancels_running_terminal_command(self):
        h = self.rt.agent.submit(SLEEP_CMD)
        time.sleep(1.0)
        t0 = time.monotonic()
        stop = self.ask("stop", timeout=10)
        h.wait(8)
        self.assertEqual(h.task.outcome, Outcome.CANCELLED, h.task.final_response)
        self.assertLess(time.monotonic() - t0, 5)
        self.assertNotIn("done", (h.task.final_response or "").lower())
        self.assertIn("Stopped", stop.final_response or "")

    def test_failure_text_never_claims_success(self):
        for text in (f"run command: nonexistent_binary_{os.getpid()}", f"read the file {self.dir / 'missing.txt'}"):
            t = self.ask(text)
            self.assertNotIn(t.outcome, {Outcome.VERIFIED, Outcome.REPLY}, (text, t.final_response))
            claims = success_claims(t.final_response or "")
            self.assertEqual(claims, [], f"{text}: false success claim {claims} in {t.final_response!r}")

    def test_fs_read_result_is_untrusted(self):
        f = self.dir / "note.txt"; f.write_text("hello world")
        t = self.ask(f"read the file {f}")
        results = [s.result for s in t.step_states.values() if s.result]
        self.assertTrue(results, t.final_response)
        self.assertTrue(any(r.taint.value == "untrusted" for r in results), [r.taint for r in results])

    def test_notes_roundtrip_via_agent(self):
        t = self.ask("take a note: m1 scenario note body")
        self.assertEqual(t.outcome, Outcome.VERIFIED, t.final_response)
        files = list(self.rt.dirs.notes.rglob("*"))
        self.assertTrue(any("m1 scenario note body" in p.read_text() for p in files if p.is_file()))

    def test_search_skips_sensitive_names(self):
        (self.dir / "id_rsa").write_text("PRIVATE KEY canary"); (self.dir / "id_rsa_notes.txt").write_text("ok")
        t = self.ask(f"find files named id_rsa in {self.dir}")
        self.assertNotIn("PRIVATE KEY canary", t.final_response or "")
        for s in t.step_states.values():
            if s.result and s.result.data:
                self.assertNotIn(str(self.dir / "id_rsa"), [h.get("path") for h in s.result.data.get("hits", [])])


@tags("INTEGRATION")
class AuditAndLogs(unittest.TestCase):
    def test_secret_in_request_never_lands_in_audit_or_logs(self):
        rt, home = make_runtime()
        try:
            secret = "sk-canary-AUDITLOG-424242"
            rt.redactor.register(secret) if hasattr(rt, "redactor") else None
            from jarvis.security.redact import REDACTOR
            REDACTOR.register(secret)
            rt.agent.run(f"run command: hostname --api-key {secret}", timeout=30)
            blob = b"".join(p.read_bytes() for p in Path(home).rglob("*") if p.is_file())
            self.assertNotIn(secret.encode(), blob)
        finally:
            dispose(rt, home)

    def test_audit_tamper_detected(self):
        import sqlite3
        rt, home = make_runtime()
        try:
            rt.agent.run("what is my hostname", timeout=30)
            self.assertTrue(rt.audit.verify().ok)
            db = rt.dirs.db / "audit.db"
            con = sqlite3.connect(db)
            with self.assertRaises(sqlite3.IntegrityError):  # layer 1: triggers refuse UPDATE
                con.execute("update audit set payload = payload || ' ' where seq = 2")
            for trg in ("audit_no_update", "audit_no_delete"):  # layer 2: an attacker with file access drops them
                con.execute(f"drop trigger {trg}")
            con.execute("update audit set payload = payload || ' ' where seq = 2")
            con.commit(); con.close()
            rep = rt.audit.verify()
            self.assertFalse(rep.ok)
        finally:
            dispose(rt, home)


@tags("UNIT")
class SuccessClaimDetector(unittest.TestCase):
    def test_honest_negations_are_not_claims(self):
        for ok in ("I have not done anything.", "Nothing was done.", "I could not complete it, so no success to report.",
                   "The command failed; it never succeeded.", "I did not do anything: not done."):
            self.assertEqual(success_claims(ok), [], ok)

    def test_real_claims_are_detected(self):
        for bad in ("Done.", "All set!", "I could not find it. Done.", "Completed successfully.", "The file was read. Success"):
            self.assertTrue(success_claims(bad), bad)
