"""Cancel token, redaction, audit chain, config precedence, manifest contracts."""

import os
import sqlite3
import tempfile
import threading
import time
import unittest
from pathlib import Path

from jarvis.common.cancel import CancelToken
from jarvis.config.loader import load_config
from jarvis.core.models import RiskLevel, SideEffect
from jarvis.registry.registry import ToolRegistry, check_manifest
from jarvis.security.audit import AuditLog
from jarvis.security.redact import Redactor
from jarvis.tools._manifest import build_manifest, obj


class CancelTokenTests(unittest.TestCase):
    def test_parent_cancel_propagates_to_child(self):
        p = CancelToken(); c = p.child()
        self.assertFalse(c.is_set())
        p.cancel("x")
        self.assertTrue(c.is_set())

    def test_wait_wakes_on_cancel(self):
        t = CancelToken()
        threading.Timer(0.05, t.cancel).start()
        t0 = time.monotonic()
        self.assertTrue(t.wait(5))
        self.assertLess(time.monotonic() - t0, 1)


class RedactionTests(unittest.TestCase):
    def test_key_value_and_registered_secrets_scrubbed(self):
        r = Redactor()
        r.register("canary-SECRET-12345")
        out = r.scrub({"api_key": "abc", "note": "token is canary-SECRET-12345", "ok": "fine",
                       "nested": {"password": "hunter2"}})
        flat = repr(out)
        for leaked in ("abc'", "canary-SECRET-12345", "hunter2"):
            self.assertNotIn(leaked, flat)
        self.assertIn("fine", flat)


class AuditTests(unittest.TestCase):
    def setUp(self):
        self.d = tempfile.mkdtemp(); self.p = Path(self.d) / "a.db"
        self.log = AuditLog(self.p)

    def tearDown(self):
        self.log.close()

    def test_chain_verifies_and_survives_reopen(self):
        for i in range(5):
            self.log.append("k", f"t{i}", n=i)
        self.assertTrue(self.log.verify().ok)
        self.log.close()
        again = AuditLog(self.p)
        again.append("k", None, n=99)
        self.assertTrue(again.verify().ok)
        self.assertEqual(again.count(), 6)
        again.close()
        self.log = AuditLog(self.p)

    def test_update_and_delete_rejected_by_triggers(self):
        self.log.append("k", "t", n=1)
        raw = sqlite3.connect(self.p)
        with self.assertRaises(sqlite3.DatabaseError):
            raw.execute("UPDATE audit SET kind='x'")
        with self.assertRaises(sqlite3.DatabaseError):
            raw.execute("DELETE FROM audit")
        raw.close()

    def test_tampering_detected_even_if_triggers_dropped(self):
        for i in range(3):
            self.log.append("k", "t", n=i)
        raw = sqlite3.connect(self.p, isolation_level=None)
        raw.execute("DROP TRIGGER audit_no_update")
        raw.execute("UPDATE audit SET payload='{\"n\":777}' WHERE seq=2")
        raw.close()
        rep = self.log.verify()
        self.assertFalse(rep.ok)
        self.assertEqual(rep.first_bad_seq, 2)

    def test_secret_never_reaches_disk(self):
        self.log.append("k", "t", api_key="canary-AUDIT-999", note="x")
        self.log.close()
        blob = self.p.read_bytes()
        wal = Path(str(self.p) + "-wal")
        if wal.exists():
            blob += wal.read_bytes()
        self.assertNotIn(b"canary-AUDIT-999", blob)
        self.log = AuditLog(self.p)


class ConfigTests(unittest.TestCase):
    def test_env_overrides_toml_overrides_default(self):
        home = tempfile.mkdtemp()
        cfg, _ = load_config(env={"JARVIS_HOME": home, "JARVIS_POLICY__MODE": "RESTRICTED"})
        self.assertEqual(cfg.policy.mode.value if hasattr(cfg.policy.mode, "value") else cfg.policy.mode, "RESTRICTED")
        cfg2, _ = load_config(env={"JARVIS_HOME": home})
        self.assertEqual(str(getattr(cfg2.policy.mode, "value", cfg2.policy.mode)), "NORMAL")


class ManifestContractTests(unittest.TestCase):
    def test_builtin_manifests_satisfy_contract(self):
        r = ToolRegistry(); r.load_builtin()
        self.assertEqual([str(v) for v in r.validate_all()], [])
        self.assertGreaterEqual(len(r.names()), 9)

    def _m(self, **kw):
        base = dict(permissions=["system.read"], postcondition=None)
        base.update(kw)
        return build_manifest("test.contract", "A manifest used to probe contract rules.",
                              kw.pop("inp", obj({})), obj({}), **{k: v for k, v in base.items()})

    def test_contract_requires_postcondition(self):
        self.assertTrue(any("postcondition" in p for p in check_manifest(self._m())))

    def test_contract_rejects_open_input_schema(self):
        m = build_manifest("test.contract", "A manifest used to probe contract rules.",
                           obj({}, extra=True), obj({}), permissions=["system.read"])
        self.assertTrue(any("additionalProperties" in p for p in check_manifest(m)))

    def test_contract_rejects_unknown_permission(self):
        m = build_manifest("test.contract", "A manifest used to probe contract rules.",
                           obj({}), obj({}), permissions=["root.everything"])
        self.assertTrue(any("permission" in p for p in check_manifest(m)))


if __name__ == "__main__":
    unittest.main()
