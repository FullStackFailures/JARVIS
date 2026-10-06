"""CLI -> jarvisd -> IPC, with the REAL Daemon (in a thread) and REAL IpcClient / CLI subprocess.
Transport is AF_UNIX on Linux and a named pipe on Windows (Windows path: NOT VERIFIED until run on Windows CI)."""

import os
import shutil
import subprocess
import sys
import tempfile
import threading
import time
import unittest
from multiprocessing.connection import Client
from pathlib import Path

from jarvis.config.schema import JarvisConfig
from jarvis.core.runtime import temp_home
from jarvis.daemon.server import AlreadyRunning, Daemon
from jarvis.ipc import auth
from jarvis.ipc import protocol as P
from jarvis.ipc.handshake import HandshakeError, client_handshake
from jarvis.ipc.client import DaemonUnavailable, IpcClient
from tests.harness import linux_only, tags

ROOT = Path(__file__).resolve().parents[2]
SLEEP_CMD = "run command: ping -n 30 127.0.0.1" if sys.platform == "win32" else "run command: sleep 30"


def start_daemon(home=None, ipc=None, **kw):
    home = home or temp_home()
    cfg = JarvisConfig(home_override=home, **({"ipc": ipc} if ipc else {}))
    d = Daemon.create(cfg, use_keyring=False, **kw)
    th = threading.Thread(target=d.serve_forever, daemon=True)
    th.start()
    for _ in range(100):
        try:
            IpcClient(d.endpoint, d.run_dir).close()
            return d, th, home
        except DaemonUnavailable:
            time.sleep(0.05)
    raise AssertionError("daemon did not start")


@tags("INTEGRATION")
class DaemonIpc(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.d, cls.th, cls.home = start_daemon()

    @classmethod
    def tearDownClass(cls):
        cls.d.stop(); cls.th.join(10)
        shutil.rmtree(cls.home, ignore_errors=True)

    def client(self):
        return IpcClient(self.d.endpoint, self.d.run_dir)

    def test_ping_and_status(self):
        with self.client() as c:
            self.assertEqual(c.ping().protocol, 1)
            st = c.status()
            self.assertEqual(st["platform"], self.d.rt.osal.name)
            self.assertGreaterEqual(len(c.tools()), 10)

    def test_greeting_uses_no_tools_and_is_a_reply(self):
        with self.client() as c:
            r = c.ask("Hello.")
        self.assertEqual(r.outcome, "REPLY")
        self.assertFalse(r.task["step_states"])

    def test_real_request_through_daemon(self):
        with self.client() as c:
            r = c.ask("what is my hostname")
        self.assertEqual(r.outcome, "VERIFIED")

    def test_denied_command_never_prompts(self):
        prompts = []
        with self.client() as c:
            r = c.ask("run command: rm -rf /tmp/never", on_approval=lambda p: prompts.append(p) or True)
        self.assertEqual(r.outcome, "FAILED")
        self.assertFalse(prompts)
        self.assertIn("denied by policy", r.text)

    def test_approval_declined_without_callback(self):
        with self.client() as c:
            r = c.ask("run command: hostname -f" if False else "run command: whoami --all")
        self.assertNotEqual(r.outcome, "VERIFIED")

    def test_approval_round_trip_approved(self):
        seen = []
        target = Path(tempfile.mkdtemp()) / "touched"
        with self.client() as c:
            r = c.ask(f"run command: touch {target}" if sys.platform != "win32" else "run command: ping -n 1 127.0.0.1",
                      on_approval=lambda p: seen.append(p) or True)
        self.assertTrue(seen, "no approval prompt was delivered")
        self.assertEqual(seen[0].tool, "terminal.execute")
        self.assertEqual(r.outcome, "VERIFIED", r.text)
        if sys.platform != "win32":
            self.assertTrue(target.exists())

    def test_cancel_from_another_client_kills_running_task(self):
        res = {}

        def long():
            with self.client() as c2:
                res["r"] = c2.ask(SLEEP_CMD, on_approval=lambda p: True)

        t = threading.Thread(target=long); t.start()
        time.sleep(2.0)
        t0 = time.monotonic()
        with self.client() as c:
            self.assertEqual(c.cancel()["cancelled"], 1)
        t.join(10)
        self.assertEqual(res["r"].outcome, "CANCELLED")
        self.assertLess(time.monotonic() - t0, 5)

    def test_client_disconnect_cancels_its_tasks(self):
        c = self.client()
        c.send(P.SubmitRequest(id="req_x1", text=SLEEP_CMD, source="text"))
        got_approval = False
        deadline = time.monotonic() + 10
        while time.monotonic() < deadline and not got_approval:
            m = c.recv(1.0)
            if isinstance(m, P.ApprovalPrompt):
                c.send(P.ApproveRequest(id="req_x2", request_id=m.request_id, approved=True)); got_approval = True
        self.assertTrue(got_approval)
        time.sleep(1.0)
        self.assertGreaterEqual(self.d.rt.tasks.active().__len__(), 1)
        c.close()
        for _ in range(60):
            if not self.d.rt.tasks.active():
                break
            time.sleep(0.1)
        self.assertEqual(len(self.d.rt.tasks.active()), 0, "orphaned task kept running after client left")

    def test_bad_token_rejected(self):
        raw = Client(self.d.endpoint.address, family=self.d.endpoint.family)
        try:
            with self.assertRaises(HandshakeError):
                client_handshake(raw, b"wrong-token-wrong-token", 3.0)
        finally:
            raw.close()
        with self.client() as c:  # daemon still healthy
            c.ping()

    def test_other_session_cannot_answer_my_approval(self):
        c1 = self.client(); c2 = self.client()
        try:
            c1.send(P.SubmitRequest(id="req_a", text="run command: ping -n 1 127.0.0.1" if sys.platform == "win32"
                                    else "run command: touch /tmp/jarvis-ipc-owner-test", source="text"))
            prompt = None
            deadline = time.monotonic() + 10
            while time.monotonic() < deadline and prompt is None:
                m = c1.recv(1.0)
                if isinstance(m, P.ApprovalPrompt):
                    prompt = m
            self.assertIsNotNone(prompt)
            with self.assertRaises((RuntimeError, TimeoutError)):  # c2 is not the owner
                c2.call(P.ApproveRequest(id="req_b", request_id=prompt.request_id, approved=True))
            c1.send(P.ApproveRequest(id="req_c", request_id=prompt.request_id, approved=False))
            while True:
                m = c1.recv(10.0)
                if isinstance(m, P.TaskResult):
                    self.assertNotEqual(m.outcome, "VERIFIED"); break
        finally:
            c1.close(); c2.close()
            try:
                os.unlink("/tmp/jarvis-ipc-owner-test")
            except OSError:
                pass

    def test_malformed_frame_does_not_kill_daemon(self):
        c = self.client()
        c._conn.send_bytes(b"{not json")
        m = c.recv(5.0)
        self.assertIsInstance(m, P.ErrorReply)
        c.close()
        with self.client() as c2:
            c2.ping()

    def test_oversized_frame_is_dropped_not_fatal(self):
        c = self.client()
        try:
            c._conn.send_bytes(b"x" * (P.MAX_CLIENT_FRAME + 10))
        except OSError:
            pass
        c.close()
        with self.client() as c2:
            c2.ping()

    def test_second_daemon_on_same_home_refuses(self):
        d2 = Daemon.create(self.d.rt.config, use_keyring=False)
        try:
            with self.assertRaises(AlreadyRunning):
                d2.serve_forever()
        finally:
            d2.rt.close()

    def test_audit_records_ipc_and_chain_verifies(self):
        with self.client() as c:
            c.ask("what is my hostname")
        self.assertTrue(self.d.rt.audit.verify().ok)


@tags("INTEGRATION")
class DaemonLifecycle(unittest.TestCase):
    def test_stale_endpoint_is_replaced_and_cleanup_removes_artifacts(self):
        home = temp_home()
        try:
            d, th, _ = start_daemon(home)
            d.stop(); th.join(10)
            self.assertIsNone(auth.read_token(d.run_dir), "token file not removed at shutdown")
            if d.endpoint.cleanup_path:
                self.assertFalse(os.path.exists(d.endpoint.cleanup_path), "socket file left behind")
            d2, th2, _ = start_daemon(home)  # restart on same home must work
            with IpcClient(d2.endpoint, d2.run_dir) as c:
                c.ping()
            d2.stop(); th2.join(10)
        finally:
            shutil.rmtree(home, ignore_errors=True)

    def test_unreachable_when_no_daemon(self):
        home = temp_home()
        try:
            d = Daemon.create(JarvisConfig(home_override=home), use_keyring=False)
            with self.assertRaises(DaemonUnavailable):
                IpcClient(d.endpoint, d.run_dir)
            d.rt.close()
        finally:
            shutil.rmtree(home, ignore_errors=True)

    @linux_only
    def test_socket_and_token_permissions(self):
        home = temp_home()
        try:
            d, th, _ = start_daemon(home)
            self.assertEqual(os.stat(d.endpoint.address).st_mode & 0o777, 0o600)
            tok = next(Path(d.run_dir).glob("*token*"))
            self.assertEqual(os.stat(tok).st_mode & 0o777, 0o600)
            self.assertEqual(os.stat(d.run_dir).st_mode & 0o777, 0o700)
            d.stop(); th.join(10)
        finally:
            shutil.rmtree(home, ignore_errors=True)


@tags("INTEGRATION")
class CliSubprocess(unittest.TestCase):
    """The shipped CLI as a subprocess against a daemon subprocess."""

    @classmethod
    def setUpClass(cls):
        cls.home = tempfile.mkdtemp()
        cls.env = dict(os.environ, PYTHONPATH=str(ROOT / "src"))
        cls.proc = subprocess.Popen([sys.executable, "-m", "jarvis.daemon", "--home", cls.home], env=cls.env,
                                    stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
        for _ in range(100):
            if cls.cli("daemon", "status").returncode == 0:
                return
            time.sleep(0.1)
        cls.proc.kill()
        raise AssertionError("jarvisd subprocess did not come up")

    @classmethod
    def cli(cls, *a, stdin=subprocess.DEVNULL):
        return subprocess.run([sys.executable, "-m", "jarvis", "--home", cls.home, *a], env=cls.env,
                              capture_output=True, text=True, timeout=60, stdin=stdin)

    @classmethod
    def tearDownClass(cls):
        cls.cli("daemon", "stop")
        try:
            cls.proc.wait(10)
        except subprocess.TimeoutExpired:
            cls.proc.kill()
        shutil.rmtree(cls.home, ignore_errors=True)

    def test_ask_verified_exit_zero(self):
        r = self.cli("ask", "get", "my", "IP")
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertIn("[VERIFIED]", r.stdout)

    def test_ask_failed_exit_nonzero_and_never_done(self):
        r = self.cli("ask", "run command: rm -rf /tmp/x")
        self.assertEqual(r.returncode, 1)
        self.assertIn("[FAILED]", r.stdout)
        self.assertNotIn("done", r.stdout.lower())

    def test_noninteractive_approval_fails_closed_and_yes_flag_approves(self):
        cmd = "run command: ping -n 1 127.0.0.1" if sys.platform == "win32" else f"run command: touch {self.home}/f"
        r = self.cli("ask", cmd)
        self.assertEqual(r.returncode, 1)
        self.assertIn("declined", r.stderr + r.stdout)
        r = self.cli("--yes", "ask", cmd)
        self.assertEqual(r.returncode, 0, r.stderr + r.stdout)

    def test_yes_flag_does_not_bypass_deny(self):
        r = self.cli("--yes", "ask", "run command: rm -rf /tmp/x")
        self.assertEqual(r.returncode, 1)
        self.assertIn("denied by policy", r.stdout)
        self.assertNotIn("--yes given", r.stderr)

    def test_status_reports_daemon_source(self):
        r = self.cli("--status")
        self.assertIn("jarvisd: RUNNING", r.stdout)

    def test_audit_verify_subcommand(self):
        self.assertIn("audit chain OK", self.cli("audit", "verify").stdout)

    def test_ask_without_daemon_is_exit_3_with_instruction(self):
        other = tempfile.mkdtemp()
        try:
            r = subprocess.run([sys.executable, "-m", "jarvis", "--home", other, "ask", "hello"], env=self.env,
                               capture_output=True, text=True, timeout=30, stdin=subprocess.DEVNULL)
            self.assertEqual(r.returncode, 3)
            self.assertIn("not running", r.stderr)
        finally:
            shutil.rmtree(other, ignore_errors=True)
