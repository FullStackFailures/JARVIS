"""H-2 regression tests: the daemon authenticates in per-connection threads under a deadline.
Real Daemon, real sockets/pipes, real clients - no mocks. Cross-platform (Windows named-pipe run: NOT VERIFIED)."""

import os
import shutil
import tempfile
import threading
import time
import unittest
from multiprocessing.connection import Client, Listener

from jarvis.core.runtime import temp_home
from jarvis.ipc import auth
from jarvis.ipc.client import DaemonUnavailable, IpcClient
from jarvis.ipc.handshake import MAGIC, NONCE_LEN
from tests.harness import linux_only, tags
from tests.integration.test_daemon import start_daemon


def raw(d):
    return Client(d.endpoint.address, family=d.endpoint.family)


def closed_by_peer(conn, within_s):
    """True if the daemon closes this (silent) connection within ``within_s`` seconds."""
    deadline = time.monotonic() + within_s
    while time.monotonic() < deadline:
        try:
            if conn.poll(0.1):
                conn.recv_bytes()  # the hello frame, then EOF later
        except (EOFError, OSError):
            return True
    return False


@tags("INTEGRATION")
class HandshakeDoesNotBlockAccept(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.d, cls.th, cls.home = start_daemon(ipc={"handshake_timeout_s": 1.5, "max_pending_handshakes": 4})

    @classmethod
    def tearDownClass(cls):
        cls.d.stop(); cls.th.join(10)
        shutil.rmtree(cls.home, ignore_errors=True)

    def audit_kinds(self, n=200):
        return [e.kind for e in self.d.rt.audit.tail(n)]

    def test_silent_clients_do_not_delay_a_legitimate_client(self):
        silent = [raw(self.d) for _ in range(3)]  # connected, never answer the challenge
        try:
            t0 = time.monotonic()
            with IpcClient(self.d.endpoint, self.d.run_dir) as c:
                self.assertEqual(c.ping().protocol, 1)
            self.assertLess(time.monotonic() - t0, 1.0, "legit client waited behind silent ones")
        finally:
            for s in silent:
                s.close()

    def test_silent_client_is_dropped_after_the_deadline(self):
        s = raw(self.d)
        try:
            self.assertTrue(closed_by_peer(s, 1.5 + 2.0), "daemon kept an unauthenticated connection open")
        finally:
            s.close()

    def test_pending_handshake_cap_sheds_extras_and_recovers(self):
        held = [raw(self.d) for _ in range(4)]  # fills all slots
        extra = []
        try:
            time.sleep(0.3)
            extra = [raw(self.d) for _ in range(3)]
            self.assertTrue(all(closed_by_peer(e, 1.0) for e in extra), "extra connections were not shed")
            self.assertTrue(all(closed_by_peer(h, 1.5 + 2.0) for h in held))
            time.sleep(0.3)
            with IpcClient(self.d.endpoint, self.d.run_dir) as c:  # slots freed again
                c.ping()
        finally:
            for x in held + extra:
                x.close()

    def test_garbage_and_oversized_replies_are_dropped_and_daemon_survives(self):
        for payload in (b"\x00\x01\x02garbage", b"A" * 5000, b"{\"type\":\"ping\",\"id\":\"x\",\"v\":1}"):
            c = raw(self.d)
            try:
                c.recv_bytes()          # hello
                c.send_bytes(payload)
                self.assertTrue(closed_by_peer(c, 3.0), f"payload {payload[:12]!r} kept the connection open")
            finally:
                c.close()
        with IpcClient(self.d.endpoint, self.d.run_dir) as c:
            c.ping()

    def test_unauthenticated_request_is_never_served(self):
        c = raw(self.d)
        try:
            c.recv_bytes()
            c.send_bytes(b'{"v":1,"id":"r1","type":"status"}')
            self.assertTrue(closed_by_peer(c, 3.0))
        finally:
            c.close()

    def test_failed_auth_audit_is_rate_limited(self):
        before = self.audit_kinds().count("ipc.auth_failed")
        for _ in range(25):
            c = raw(self.d)
            try:
                c.recv_bytes(); c.send_bytes(b"x" * 64)
            except (EOFError, OSError):
                pass
            finally:
                c.close()
        time.sleep(0.5)
        after = self.audit_kinds().count("ipc.auth_failed")
        self.assertGreaterEqual(after - before, 1)
        self.assertLess(after - before, 12, "attacker-controlled volume must not flood the audit log")
        self.assertTrue(self.d.rt.audit.verify().ok)


@tags("INTEGRATION")
class PeerIdentityPolicy(unittest.TestCase):
    """The daemon's decision logic around ``peer_is_current_user`` (the OSAL answer is substituted per test)."""

    def run_with(self, answer, require=True):
        d, th, home = start_daemon(ipc={"require_peer_identity": require, "handshake_timeout_s": 2.0})
        real = d.rt.osal.peer_is_current_user
        d.rt.osal.peer_is_current_user = answer if callable(answer) else (lambda fd: answer)
        try:
            try:
                with IpcClient(d.endpoint, d.run_dir, timeout_s=2.0, handshake_timeout_s=2.0) as c:
                    c.ping()
                admitted = True
            except (DaemonUnavailable, EOFError, OSError, TimeoutError):
                admitted = False
            kinds = [e.kind for e in d.rt.audit.tail(100)]
        finally:
            d.rt.osal.peer_is_current_user = real
            d.stop(); th.join(10)
            shutil.rmtree(home, ignore_errors=True)
        return admitted, kinds

    def test_matching_identity_is_admitted(self):
        self.assertTrue(self.run_with(True)[0])

    def test_foreign_identity_is_rejected_before_any_handshake(self):
        admitted, kinds = self.run_with(False)
        self.assertFalse(admitted)
        self.assertIn("ipc.peer_rejected", kinds)

    def test_undeterminable_identity_fails_closed_by_default(self):
        admitted, kinds = self.run_with(None)
        self.assertFalse(admitted)
        self.assertIn("ipc.peer_rejected", kinds)

    def test_undeterminable_identity_allowed_only_when_explicitly_configured(self):
        self.assertTrue(self.run_with(None, require=False)[0])

    def test_crashing_identity_check_rejects(self):
        def boom(fd):
            raise RuntimeError("adapter bug")

        self.assertFalse(self.run_with(boom)[0])


@tags("INTEGRATION")
class ImpostorServer(unittest.TestCase):
    """A process that squats the endpoint but cannot read the token must be refused by the CLIENT."""

    @linux_only
    def test_client_refuses_a_server_that_does_not_know_the_token(self):
        run_dir = __import__("pathlib").Path(tempfile.mkdtemp(dir="/tmp"))
        sock = str(run_dir / "x.sock")
        auth.write_token(run_dir)
        listener = Listener(sock, family="AF_UNIX")

        def fake_server():
            try:
                c = listener.accept()
                c.send_bytes(MAGIC + os.urandom(NONCE_LEN))
                c.recv_bytes()
                c.send_bytes(os.urandom(32))
                time.sleep(0.5)
            except (OSError, EOFError):
                pass

        threading.Thread(target=fake_server, daemon=True).start()
        from jarvis.osal.types import IpcEndpoint
        try:
            with self.assertRaises(DaemonUnavailable) as cm:
                IpcClient(IpcEndpoint(family="AF_UNIX", address=sock), run_dir)
            self.assertIn("impostor", str(cm.exception))
        finally:
            listener.close()
            shutil.rmtree(run_dir, ignore_errors=True)
