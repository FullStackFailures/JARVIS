"""M1 gap-closure unit tests: registry query, systemd parsing, policy rows, fail-closed executor, notes, log canary."""

import logging
import os
import tempfile
import unittest
from pathlib import Path

from jarvis.common.cancel import CancelToken
from jarvis.core.models import Decision, FailureClass, PermissionMode as M, Step, Taint
from jarvis.osal.linux.systemd import map_state, parse_show
from jarvis.policy.engine import PolicyRequest
from tests.conftest_helpers import dispose, make_runtime
from tests.harness import tags


@tags("UNIT")
class RegistryQuery(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.rt, cls.home = make_runtime()

    @classmethod
    def tearDownClass(cls):
        dispose(cls.rt, cls.home)

    def q(self, text, **kw):
        return [t.manifest.name for t in self.rt.registry.query(text, self.rt.osal.name, **kw)]

    def test_capability_lookup(self):
        self.assertEqual(self.q("what is my ip address")[0], "net.get_addresses")
        self.assertEqual(self.q("disk space")[0], "system.disk")
        self.assertEqual(self.q("is the ssh service running")[0], "system.service_status")
        self.assertEqual(self.q("save a note")[0], "notes.write")

    def test_unknown_intent_returns_nothing(self):
        self.assertEqual(self.q("zxqv frobnicate"), [])

    def test_permission_filter_excludes_tools(self):
        self.assertNotIn("notes.write", self.q("save a note", granted_perms={"system.read"}))

    def test_other_platform_filtered(self):
        other = "windows" if self.rt.osal.name == "linux" else "linux"
        names = {t.manifest.name for t in self.rt.registry.query("system", other)}
        for n in names:
            self.assertIn(other, self.rt.registry.get(n).manifest.platforms)


@tags("UNIT")
class SystemdParsing(unittest.TestCase):
    """Pure parser: validates parsing logic only. It does NOT validate systemctl behaviour on any host."""

    def test_running_enabled(self):
        raw = parse_show("LoadState=loaded\nActiveState=active\nUnitFileState=enabled\n")
        self.assertEqual(map_state(raw), ("running", True, None))

    def test_not_found(self):
        self.assertEqual(map_state(parse_show("LoadState=not-found\nActiveState=inactive\n"))[0], "not_found")

    def test_failed_and_stopped(self):
        self.assertEqual(map_state(parse_show("LoadState=loaded\nActiveState=failed\n"))[0], "failed")
        self.assertEqual(map_state(parse_show("LoadState=loaded\nActiveState=inactive\nUnitFileState=disabled\n"))[:2],
                         ("stopped", False))

    def test_garbage_is_not_a_state(self):
        self.assertIsNone(parse_show("Failed to connect to bus"))
        self.assertEqual(map_state({"LoadState": "loaded", "ActiveState": "activating"})[0], "unknown")


@tags("UNIT")
class PolicyRows(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.rt, cls.home = make_runtime()

    @classmethod
    def tearDownClass(cls):
        dispose(cls.rt, cls.home)

    def ev(self, argv, tainted=False, mode=M.NORMAL):
        m = self.rt.registry.get("terminal.execute").manifest
        return self.rt.policy.evaluate(PolicyRequest(manifest=m, arguments={"argv": argv}, mode=mode,
                                                     tainted=tainted, cwd=Path.cwd()))

    def test_destructive_commands_denied_on_both_platforms(self):
        for argv in (["rm", "-rf", "/tmp/x"], ["del", "/f", "x"], ["rmdir", "/s", "x"], ["Remove-Item", "x"],
                     ["format", "c:"], ["shutdown", "now"], ["sudo", "ls"], ["runas", "x"], ["rd", "/s", "x"]):
            with self.subTest(argv=argv):
                self.assertEqual(self.ev(argv).decision, Decision.DENY)

    def test_taint_never_auto_approves_medium(self):
        d = self.ev(["touch", "x"], tainted=True)
        self.assertNotEqual(d.decision, Decision.ALLOW)

    def test_taint_does_not_turn_deny_into_ask(self):
        self.assertEqual(self.ev(["rm", "x"], tainted=True).decision, Decision.DENY)

    def test_full_access_mode_still_denies_destructive(self):
        self.assertEqual(self.ev(["rm", "-rf", "/"], mode=M.FULL_ACCESS).decision, Decision.DENY)


@tags("UNIT")
class ExecutorFailClosed(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.rt, cls.home = make_runtime()

    @classmethod
    def tearDownClass(cls):
        dispose(cls.rt, cls.home)

    def run_step(self):
        return self.rt.executor.run_step(Step(id="s1", tool="system.hostname", arguments={}), task_id="t", results={},
                                         cancel=CancelToken(), mode=M.NORMAL)

    def test_policy_crash_means_no_execution(self):
        real = self.rt.policy.evaluate
        self.rt.policy.evaluate = lambda req: (_ for _ in ()).throw(RuntimeError("boom"))
        try:
            run = self.run_step()
        finally:
            self.rt.policy.evaluate = real
        self.assertFalse(run.result.ok)
        self.assertEqual(run.result.failure_class, FailureClass.POLICY_DENIED)
        self.assertFalse(run.result.data)

    def test_policy_returning_none_means_no_execution(self):
        real = self.rt.policy.evaluate
        self.rt.policy.evaluate = lambda req: None
        try:
            run = self.run_step()
        finally:
            self.rt.policy.evaluate = real
        self.assertFalse(run.result.ok)
        self.assertEqual(run.result.failure_class, FailureClass.POLICY_DENIED)

    def test_normal_step_carries_a_decision_and_verification(self):
        run = self.run_step()
        self.assertTrue(run.result.ok)
        self.assertIsNotNone(run.policy)
        self.assertIsNotNone(run.result.verified)


@tags("UNIT")
class NotesTool(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.rt, cls.home = make_runtime()

    @classmethod
    def tearDownClass(cls):
        dispose(cls.rt, cls.home)

    def write(self, **a):
        return self.rt.executor.run_step(Step(id="s1", tool="notes.write", arguments=a), task_id="t", results={},
                                         cancel=CancelToken(), mode=M.NORMAL)

    def test_write_is_verified_and_confined(self):
        run = self.write(title="m1-test", text="hello")
        self.assertTrue(run.result.ok, run.result.error)
        self.assertTrue(run.result.verified)
        path = Path(run.result.data["path"]).resolve()
        self.assertEqual(path.read_text(), "hello")
        self.assertTrue(str(path).startswith(str(self.rt.dirs.notes.resolve())))

    def test_path_traversal_name_cannot_escape(self):
        run = self.write(title="../../escape", text="x")
        if run.result.ok:
            p = Path(run.result.data["path"]).resolve()
            self.assertTrue(str(p).startswith(str(self.rt.dirs.notes.resolve())))
        self.assertFalse((self.rt.dirs.notes.parent.parent / "escape.md").exists())

    def test_overwrite_refused_append_works(self):
        self.assertTrue(self.write(title="dup", text="a").result.ok)
        second = self.write(name="dup", content="b")
        self.assertFalse(second.result.ok)
        app = self.write(title="dup", text="b", append=True)
        if app.result.ok:
            self.assertEqual(Path(app.result.data["path"]).read_text(), "a\nb")
        else:
            self.fail(f"append failed: {app.result.error}")


@tags("UNIT")
class LogCanary(unittest.TestCase):
    def test_secret_never_reaches_log_files(self):
        from jarvis.security.logsetup import setup_logging
        from jarvis.security.redact import REDACTOR

        secret = "canary-LOGSECRET-7781"
        REDACTOR.register(secret)
        d = tempfile.mkdtemp()
        setup_logging("DEBUG", d, True)
        log = logging.getLogger("jarvis.canary")
        log.info("token=%s password=hunter2-canary and also %s", secret, secret)
        log.error("boom api_key=%s", secret, exc_info=False)
        for h in logging.getLogger().handlers:
            h.flush()
        blob = b"".join(p.read_bytes() for p in Path(d).rglob("*") if p.is_file())
        self.assertIn(b"canary", blob)  # logging really wrote something
        self.assertNotIn(secret.encode(), blob)
        self.assertNotIn(b"hunter2-canary", blob)
