"""Pure handshake tests over an in-memory connection pair (multiprocessing.Pipe: real Connection objects, no daemon).
Runs identically on Linux and Windows."""

import hashlib
import hmac
import threading
import time
import unittest
from multiprocessing import Pipe

from jarvis.ipc.handshake import (DENIED, MAGIC, MAX_MSG, NONCE_LEN, HandshakeError, client_handshake,
                                  server_handshake)
from tests.harness import tags

KEY = b"k" * 64


def run_server(conn, key=KEY, timeout=3.0):
    box = {}

    def go():
        try:
            server_handshake(conn, key, timeout)
            box["ok"] = True
        except HandshakeError as exc:
            box["err"] = exc

    t = threading.Thread(target=go, daemon=True)
    t.start()
    return t, box


@tags("UNIT")
class Handshake(unittest.TestCase):
    def setUp(self):
        self.a, self.b = Pipe()  # a = server end, b = client end

    def tearDown(self):
        self.a.close(); self.b.close()

    def test_mutual_success(self):
        t, box = run_server(self.a)
        client_handshake(self.b, KEY, 3.0)
        t.join(5)
        self.assertTrue(box.get("ok"), box)

    def test_wrong_key_rejected_on_both_sides(self):
        t, box = run_server(self.a)
        with self.assertRaises(HandshakeError):
            client_handshake(self.b, b"x" * 64, 3.0)
        t.join(5)
        self.assertIn("err", box)

    def test_empty_key_refused(self):
        with self.assertRaises(HandshakeError):
            server_handshake(self.a, b"", 1.0)
        with self.assertRaises(HandshakeError):
            client_handshake(self.b, b"", 1.0)

    def test_silent_client_times_out_promptly(self):
        t0 = time.monotonic()
        with self.assertRaises(HandshakeError) as cm:
            server_handshake(self.a, KEY, 0.6)
        self.assertLess(time.monotonic() - t0, 2.0)
        self.assertIn("timed out", str(cm.exception))

    def test_silent_server_times_out_for_client(self):
        with self.assertRaises(HandshakeError):
            client_handshake(self.b, KEY, 0.5)

    def test_oversized_client_reply_rejected(self):
        t, box = run_server(self.a)
        self.b.recv_bytes()
        self.b.send_bytes(b"A" * (MAX_MSG * 4))
        t.join(5)
        self.assertIn("err", box)

    def test_short_reply_is_malformed(self):
        t, box = run_server(self.a)
        self.b.recv_bytes()
        self.b.send_bytes(b"short")
        t.join(5)
        self.assertIn("malformed", str(box["err"]))

    def test_peer_closing_mid_handshake(self):
        t, box = run_server(self.a)
        self.b.recv_bytes()
        self.b.close()
        t.join(5)
        self.assertIn("err", box)

    def test_impostor_server_without_key_is_detected_by_client(self):
        def impostor():
            self.a.send_bytes(MAGIC + b"\x01" * NONCE_LEN)
            self.a.recv_bytes()
            self.a.send_bytes(b"\x00" * 32)  # cannot compute the real proof

        threading.Thread(target=impostor, daemon=True).start()
        with self.assertRaises(HandshakeError) as cm:
            client_handshake(self.b, KEY, 3.0)
        self.assertIn("impostor", str(cm.exception))

    def test_reflection_attack_fails(self):
        """A server that bounces the client's own MAC back (role labels must make it invalid)."""
        def reflector():
            nonce_s = b"\x02" * NONCE_LEN
            self.a.send_bytes(MAGIC + nonce_s)
            reply = self.a.recv_bytes()
            self.a.send_bytes(reply[:32])

        threading.Thread(target=reflector, daemon=True).start()
        with self.assertRaises(HandshakeError):
            client_handshake(self.b, KEY, 3.0)

    def test_client_rejects_non_jarvis_hello(self):
        self.a.send_bytes(b"220 smtp.example.com ESMTP")
        with self.assertRaises(HandshakeError) as cm:
            client_handshake(self.b, KEY, 2.0)
        self.assertIn("not a jarvisd", str(cm.exception))

    def test_denied_marker_surfaces_clearly(self):
        def denier():
            self.a.send_bytes(MAGIC + b"\x03" * NONCE_LEN)
            self.a.recv_bytes()
            self.a.send_bytes(DENIED)

        threading.Thread(target=denier, daemon=True).start()
        with self.assertRaises(HandshakeError) as cm:
            client_handshake(self.b, KEY, 2.0)
        self.assertIn("rejected", str(cm.exception))

    def test_client_must_confirm_after_server_proof(self):
        t, box = run_server(self.a)
        hello = self.b.recv_bytes()
        nonce_s = hello[len(MAGIC):]
        nonce_c = b"\x04" * NONCE_LEN
        self.b.send_bytes(hmac.new(KEY, b"C|" + nonce_s, hashlib.sha256).digest() + nonce_c)
        self.b.recv_bytes()          # server proof
        self.b.send_bytes(b"NOPE")   # does not confirm
        t.join(5)
        self.assertIn("confirm", str(box["err"]))
