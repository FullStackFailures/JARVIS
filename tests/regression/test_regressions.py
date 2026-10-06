"""One test per production bug found during Milestone 1."""

import time
import unittest

from jarvis.common.cancel import CancelToken
from jarvis.core.models import FailureClass, Postcondition, PermissionMode as M, Step
from jarvis.tools._manifest import build_manifest, obj
from jarvis.tools.base import Tool, ToolOutput
from tests.conftest_helpers import dispose, make_runtime
from tests.harness import tags


class RaisesBuiltinTimeout(Tool):
    manifest = build_manifest("test.raise_timeout", "Raises the builtin TimeoutError directly.", obj({}),
                              obj({"a": {"type": "integer"}}, ["a"]), permissions=["system.read"],
                              postcondition=Postcondition(kind="field_present", path="data.a"))

    def execute(self, args, ctx):
        raise TimeoutError("tool raised its own timeout")


class Regressions(unittest.TestCase):
    def test_tool_raising_builtin_timeouterror_does_not_hang_executor(self):
        # 3.11+ aliases concurrent.futures.TimeoutError to TimeoutError; the executor once looped forever.
        rt, home = make_runtime(extra_tools=[RaisesBuiltinTimeout])
        try:
            t0 = time.monotonic()
            r = rt.executor.run_step(Step(id="s1", tool="test.raise_timeout"), task_id="t", results={},
                                     cancel=CancelToken(), mode=M.NORMAL)
            self.assertLess(time.monotonic() - t0, 10)
            self.assertFalse(r.result.ok)
        finally:
            dispose(rt, home)

    def test_failure_text_names_missing_browser_without_noise(self):
        rt, home = make_runtime()
        try:
            apps, _ = rt.osal.discover_applications()
            if any(a.kind == "browser" for a in apps):
                self.skipTest("browser present")
            t = rt.agent.run("open my browser", timeout=60)
            self.assertIn("No browser was found on this system.", t.final_response)
            self.assertNotIn("not attempted", t.final_response)
        finally:
            dispose(rt, home)

    def test_self_test_reports_actual_platform(self):
        import io
        import contextlib
        from jarvis.cli.selftest import run_self_test
        buf = io.StringIO()
        with contextlib.redirect_stdout(buf):
            run_self_test()
        import sys
        self.assertIn("platform: " + ("windows" if sys.platform == "win32" else "linux"), buf.getvalue())


if __name__ == "__main__":
    unittest.main()


@tags("REGRESSION", "INTEGRATION")
class AuditMultiWriter(unittest.TestCase):
    """Found by the daemon tests: jarvisd and a CLI process appended concurrently and collided on audit.seq."""

    def test_two_writers_on_one_file_keep_a_valid_chain(self):
        import tempfile
        import threading
        from pathlib import Path
        from jarvis.security.audit import AuditLog

        path = Path(tempfile.mkdtemp()) / "audit.db"
        a, b = AuditLog(path), AuditLog(path)
        errors = []

        def work(log, tag):
            try:
                for i in range(60):
                    log.append("test.event", None, writer=tag, i=i)
            except Exception as exc:  # noqa: BLE001
                errors.append(exc)

        ts = [threading.Thread(target=work, args=(a, "a")), threading.Thread(target=work, args=(b, "b"))]
        [t.start() for t in ts]; [t.join() for t in ts]
        self.assertEqual(errors, [])
        rep = a.verify()
        self.assertTrue(rep.ok, rep.reason)
        self.assertEqual(rep.entries, 120)
        a.close(); b.close()


@tags("REGRESSION")
class WindowsPathWithSpaceRouting(unittest.TestCase):
    """Found on real Windows: 'read the file C:\\Users\\Jane Doe\\...\\note.txt' was UNSUPPORTED because the read template
    stopped at the first space. The route must reach fs.read with the FULL path (the file need not exist here)."""

    @classmethod
    def setUpClass(cls):
        cls.rt, cls.home = make_runtime()

    @classmethod
    def tearDownClass(cls):
        dispose(cls.rt, cls.home)

    def test_drive_path_with_spaces_reaches_fs_read_whole(self):
        for path in (r"C:\Users\Jane Doe\AppData\Local\Temp\tmpab\note.txt", r"C:\Users\Jane Doe\note.txt."):
            t = self.rt.agent.run(f"read the file {path}", timeout=30)
            tools = [(s.tool, s.arguments.get("path")) for s in t.plan.steps]
            self.assertEqual(tools, [("fs.read", path.rstrip("."))], (path, t.final_response))

    def test_quoted_and_plain_paths_still_route(self):
        for text, want in ((r'read the file "C:\a b\c.txt"', r"C:\a b\c.txt"), ("read the file /tmp/x.txt", "/tmp/x.txt"),
                           (r"read the file C:\x\y.txt", r"C:\x\y.txt")):
            t = self.rt.agent.run(text, timeout=30)
            self.assertEqual([(s.tool, s.arguments.get("path")) for s in t.plan.steps], [("fs.read", want)], text)
