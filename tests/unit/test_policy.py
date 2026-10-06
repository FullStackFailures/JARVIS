"""Table-driven policy tests (deterministic engine; no OS access beyond path resolution)."""

import tempfile
import unittest
from pathlib import Path

from jarvis.config.schema import PolicyConfig
from jarvis.core.models import Decision, PermissionMode as M, RiskLevel
from jarvis.osal.detect import create_adapter
from jarvis.policy.engine import PolicyEngine, PolicyRequest
from jarvis.registry.registry import ToolRegistry
from tests.harness import linux_only


class PolicyTable(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.reg = ToolRegistry(); cls.reg.load_builtin()
        cls.cwd = Path(tempfile.mkdtemp()).resolve()
        cls.engine = PolicyEngine(PolicyConfig(), create_adapter(), cls.cwd)

    def ev(self, tool, args, mode=M.NORMAL, tainted=False):
        m = self.reg.get(tool).manifest
        return self.engine.evaluate(PolicyRequest(manifest=m, arguments=args, mode=mode, tainted=tainted, cwd=self.cwd))

    def test_low_risk_reads_allowed_in_every_mode(self):
        for mode in M:
            self.assertEqual(self.ev("system.hostname", {}, mode).decision, Decision.ALLOW, mode)

    def test_apps_open_denied_in_restricted_allowed_in_normal(self):
        self.assertEqual(self.ev("apps.open", {"app_id": "x"}, M.RESTRICTED).decision, Decision.DENY)
        self.assertEqual(self.ev("apps.open", {"app_id": "x"}, M.NORMAL).decision, Decision.ALLOW)

    def test_tainted_apps_open_requires_approval(self):
        self.assertEqual(self.ev("apps.open", {"app_id": "x"}, M.NORMAL, tainted=True).decision, Decision.ASK)

    @linux_only
    def test_terminal_classification(self):
        table = [
            (["uname", "-a"], Decision.ALLOW),
            (["hostname"], Decision.ALLOW),
            (["rm", "-rf", "/"], Decision.DENY),
            (["python3", "-c", "print(1)"], Decision.DENY),
            (["bash", "-c", "id"], Decision.DENY),
            (["curl", "http://example.invalid"], None),   # network egress: never silently allowed
            (["some-unknown-binary"], Decision.ASK),
        ]
        for argv, want in table:
            d = self.ev("terminal.execute", {"argv": argv}).decision
            if want is None:
                self.assertNotEqual(d, Decision.ALLOW, argv)
            else:
                self.assertEqual(d, want, argv)

    @linux_only
    def test_terminal_restricted_mode_never_executes_unknowns(self):
        self.assertEqual(self.ev("terminal.execute", {"argv": ["some-unknown-binary"]}, M.RESTRICTED).decision,
                         Decision.DENY)

    def test_sensitive_path_denied(self):
        home = Path.home()
        d = self.ev("fs.list", {"path": str(home / ".ssh")})
        self.assertEqual(d.decision, Decision.DENY)

    def test_out_of_scope_path_is_not_allowed_silently(self):
        root = Path(Path.home().anchor or "/")
        d = self.ev("fs.list", {"path": str(root / "definitely_outside_scope_dir")})
        self.assertNotEqual(d.decision, Decision.ALLOW)

    def test_in_scope_path_allowed(self):
        self.assertEqual(self.ev("fs.list", {"path": str(self.cwd)}).decision, Decision.ALLOW)

    def test_privilege_elevation_always_denied(self):
        from jarvis.core.models import ToolManifest
        from jarvis.tools._manifest import build_manifest, obj
        from jarvis.core.models import SideEffect
        m = build_manifest("priv.test_elevate", "A test manifest that requires elevation.", obj({}), obj({}),
                           risk=RiskLevel.MEDIUM, permissions=["priv.elevate"],
                           side_effects=[SideEffect.SYSTEM_MODIFY] if hasattr(SideEffect, "SYSTEM_MODIFY") else [SideEffect.NONE])
        for mode in M:
            r = self.engine.evaluate(PolicyRequest(manifest=m, arguments={}, mode=mode, cwd=self.cwd))
            self.assertEqual(r.decision, Decision.DENY, mode)
            self.assertTrue(any("unavailable" in x for x in r.reasons))


if __name__ == "__main__":
    unittest.main()
