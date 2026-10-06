"""Windows-only adapter/IPC/CLI tests. They SKIP on every other OS and exist so that the Windows CI job (and a human
following docs/WINDOWS_VERIFICATION.md) produces real evidence. Until a Windows report exists, everything exercised
here is NOT VERIFIED."""

import ipaddress
import os
import re
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

from jarvis.core.models import Outcome
from jarvis.osal.detect import create_adapter
from tests.conftest_helpers import dispose, make_runtime
from tests.harness import tags, windows_only

ROOT = Path(__file__).resolve().parents[2]


@windows_only
@tags("INTEGRATION")
class WindowsAdapter(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.osal = create_adapter()

    def test_adapter_identity_and_shell(self):
        self.assertEqual(self.osal.name, "windows")
        sh = self.osal.detect_shell()
        self.assertTrue(sh.available, "no shell found on PATH")
        self.assertTrue(set(sh.available) <= {"pwsh", "powershell", "cmd"})
        self.assertTrue(sh.default_shell, "COMSPEC not set")

    def test_service_state_for_known_services(self):
        for name in ("TermService", "Spooler", "EventLog"):
            st = self.osal.service_state(name)
            self.assertIn(st.state, {"running", "stopped", "failed", "not_found", "unknown"})
        self.assertEqual(self.osal.service_state("Definitely-Not-A-Service-9f3a").state, "not_found")

    def test_ssh_alias_resolves_to_sshd(self):
        self.assertIn("sshd", [a.lower() for a in self.osal.service_aliases("ssh")])

    def test_ipc_endpoint_is_a_named_pipe(self):
        ep = self.osal.ipc_endpoint(Path(tempfile.gettempdir()), "")
        self.assertEqual(ep.family, "AF_PIPE")
        self.assertTrue(ep.address.startswith("\\\\.\\pipe\\jarvisd-"))

    def test_port_owner_finds_own_listener(self):
        import socket
        s = socket.socket(); s.bind(("127.0.0.1", 0)); s.listen(1)
        try:
            r = self.osal.port_owner(s.getsockname()[1])
            self.assertIn(os.getpid(), [o.pid for o in r.listeners])
        finally:
            s.close()

    def test_app_discovery_returns_named_entries(self):
        apps, _notes = self.osal.discover_applications()
        self.assertTrue(apps)
        self.assertTrue(all(a.name for a in apps))

    def test_hidden_attribute_respected(self):
        d = Path(tempfile.mkdtemp()); f = d / "h.txt"; f.write_text("x")
        subprocess.run(["attrib", "+h", str(f)], check=True)
        self.assertTrue(self.osal.is_hidden(d, "h.txt"))

    def test_kill_process_tree_kills_children(self):
        p = subprocess.Popen(["cmd", "/c", "ping -n 60 127.0.0.1 > nul"], **self.osal.popen_kwargs())
        import time; time.sleep(1.0)
        self.osal.kill_process_tree(p)
        self.assertIsNotNone(p.wait(10))


@windows_only
@tags("INTEGRATION")
class WindowsPipeline(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.rt, cls.home = make_runtime(approve=True)

    @classmethod
    def tearDownClass(cls):
        dispose(cls.rt, cls.home)

    def test_ip_via_terminal_uses_a_real_windows_command(self):
        t = self.rt.agent.run("get my IP using the terminal", timeout=60)
        self.assertEqual(t.outcome, Outcome.VERIFIED, t.final_response)
        ips = re.findall(r"\b(?:\d{1,3}\.){3}\d{1,3}\b", t.final_response)
        self.assertTrue(ips)
        ipaddress.ip_address(ips[0])

    def test_destructive_powershell_and_cmd_are_denied(self):
        for cmd in ("del /f C:\\x", "Remove-Item C:\\x", "rd /s C:\\x", "powershell -c whoami"):
            t = self.rt.agent.run(f"run command: {cmd}", timeout=30)
            self.assertEqual(t.outcome, Outcome.FAILED, cmd)
            self.assertIn("denied by policy", t.final_response)

    def test_ssh_status_is_a_real_state_or_honest(self):
        t = self.rt.agent.run("check whether SSH is running", timeout=60)
        self.assertNotIn("done", t.final_response.lower())

    def test_doctor_and_self_test_exit_zero(self):
        env = dict(os.environ, PYTHONPATH=str(ROOT / "src"), JARVIS_HOME=tempfile.mkdtemp())
        for flag in ("--doctor", "--self-test"):
            r = subprocess.run([sys.executable, "-m", "jarvis", flag], env=env, capture_output=True, text=True, timeout=300)
            self.assertEqual(r.returncode, 0, r.stdout + r.stderr)
            self.assertIn("windows", r.stdout.lower())


@windows_only("needs real Win32 security APIs: named-pipe DACLs, GetNamedPipeClientProcessId, token SIDs")
@tags("INTEGRATION", "SECURITY")
class WindowsIpcHardening(unittest.TestCase):
    """H-1 evidence. Until these pass on Windows/CI the hardening is IMPLEMENTED + NOT VERIFIED.
    A failure of the DACL read-back test is informative (it may be our read-back method, not the pipe) and must be
    investigated, never silenced."""

    @classmethod
    def setUpClass(cls):
        from jarvis.osal.windows.pipe_policy import owner_only_pipe_sddl
        cls.osal = create_adapter()
        cls.api = cls.osal._security()
        cls.sid = cls.api.current_user_sid()
        cls.sddl = owner_only_pipe_sddl(cls.sid)

    def _pipe_name(self):
        from jarvis.osal.windows.pipe_policy import pipe_address
        return pipe_address(self.sid, "t" + os.urandom(4).hex())

    def test_endpoint_is_named_by_sid_not_by_user_name(self):
        ep = self.osal.ipc_endpoint(Path(tempfile.gettempdir()), "")
        self.assertIn(self.sid, ep.address)
        self.assertNotIn(os.environ.get("USERNAME", "\0"), ep.address.replace(self.sid, ""))

    def test_pipe_dacl_is_owner_only(self):
        from jarvis.osal.windows.pipe_policy import dacl_grants_only
        name = self._pipe_name()
        h = self.api.create_secure_pipe(name, self.sddl, first=True)
        try:
            sddl = self.api.read_dacl_sddl(name)
            self.assertTrue(dacl_grants_only(sddl, self.sid), f"unexpected pipe DACL: {sddl}")
        finally:
            self.api.close_handle(h)

    def test_first_instance_blocks_squatting(self):
        from jarvis.osal.types import OsalError
        name = self._pipe_name()
        h = self.api.create_secure_pipe(name, self.sddl, first=True)
        try:
            with self.assertRaises(OsalError):
                self.api.create_secure_pipe(name, self.sddl, first=True)
        finally:
            self.api.close_handle(h)

    def test_peer_verification_with_a_real_child_process(self):
        """The peer PID must be the PID of the process that actually connected.

        Popen.pid is NOT that PID inside a virtual environment: venv's python.exe is a launcher that starts the base
        interpreter as a child, so the process holding the pipe is a descendant of Popen.pid (found on real Windows:
        expected launcher PID 13196, pipe reported 5688). The child therefore reports its own os.getpid(), and we also
        require that PID to belong to the process tree we spawned."""
        import psutil
        from jarvis.osal.windows.pipe import SecurePipeListener, verify_peer
        name = self._pipe_name()
        lst = SecurePipeListener(name, self.sddl, self.api)
        code = ("import os,sys,time;print(os.getpid(),flush=True);"
                "from multiprocessing.connection import Client;"
                f"c=Client({name!r},family='AF_PIPE');time.sleep(20)")
        child = subprocess.Popen([sys.executable, "-c", code], stdout=subprocess.PIPE, text=True)
        try:
            actual_pid = int(child.stdout.readline().strip())
            conn = lst.accept()
            reported = self.api.client_pid(conn._handle)
            tree = {child.pid} | {c.pid for c in psutil.Process(child.pid).children(recursive=True)}
            detail = f"Popen.pid={child.pid} child-reported={actual_pid} pipe-reported={reported} tree={sorted(tree)}"
            self.assertEqual(reported, actual_pid, detail)
            self.assertIn(reported, tree, detail)
            self.assertIs(verify_peer(self.api, conn._handle, self.sid), True)
            self.assertFalse(verify_peer(self.api, conn._handle, self.sid + "9"))
            self.assertTrue(self.osal.peer_is_current_user(conn._handle))
            conn.close()
        finally:
            try:  # the launcher's child (the real interpreter) would otherwise outlive the test for ~20 s
                for c in psutil.Process(child.pid).children(recursive=True):
                    c.kill()
            except psutil.Error:
                pass
            child.kill(); child.wait(10); lst.close()

    def test_token_file_and_run_dir_are_owner_only(self):
        from jarvis.ipc.auth import TOKEN_FILE, write_token
        from jarvis.osal.windows.pipe_policy import dacl_grants_only
        d = Path(tempfile.mkdtemp())
        write_token(d, self.osal)
        for p in (d / TOKEN_FILE, d):
            sddl = self.api.read_dacl_sddl(str(p))
            self.assertTrue(dacl_grants_only(sddl, self.sid), f"{p}: {sddl}")

    def test_real_daemon_round_trip_over_secure_pipe(self):
        import shutil
        from jarvis.ipc.client import IpcClient
        from tests.integration.test_daemon import start_daemon
        d, th, home = start_daemon()
        try:
            self.assertIn(self.sid, d.endpoint.address)
            with IpcClient(d.endpoint, d.run_dir) as c:
                self.assertEqual(c.ping().protocol, 1)
        finally:
            d.stop(); th.join(10)
            shutil.rmtree(home, ignore_errors=True)
