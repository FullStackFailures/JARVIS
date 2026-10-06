"""Real OSAL behaviour on this machine. Linux-tagged: skipped (with reason) elsewhere."""

import os
import socket
import sys
import tempfile
import time
import unittest
from pathlib import Path

from jarvis.common.cancel import CancelToken
from jarvis.osal.detect import create_adapter
from jarvis.osal.inventory import build_inventory
from jarvis.osal.types import OsalError
from tests.harness import linux_only, tags


class CrossPlatformOsal(unittest.TestCase):
    """Runs on whichever OS the suite runs on (tagged by the OS actually executed)."""

    @classmethod
    def setUpClass(cls):
        cls.a = create_adapter()

    def test_adapter_matches_host(self):
        self.assertEqual(self.a.name, "windows" if sys.platform == "win32" else "linux")

    def test_hostname_matches_stdlib(self):
        self.assertEqual(self.a.hostname()["hostname"], socket.gethostname())

    def test_memory_sane(self):
        m = self.a.memory()
        self.assertGreater(m.total, 0)
        self.assertLessEqual(m.available, m.total)

    def test_run_process_captures_output_and_exit_code(self):
        r = self.a.run_process([sys.executable, "-c", "import sys;print('out');sys.stderr.write('err');sys.exit(3)"],
                               cwd=Path.cwd(), env=None, timeout_s=20, cancel=CancelToken())
        self.assertEqual(r.exit_code, 3)
        self.assertIn("out", r.stdout)
        self.assertIn("err", r.stderr)

    def test_run_process_timeout_kills_tree(self):
        t0 = time.monotonic()
        r = self.a.run_process([sys.executable, "-c", "import time;time.sleep(30)"], cwd=Path.cwd(), env=None, timeout_s=0.5, cancel=CancelToken())
        self.assertLess(time.monotonic() - t0, 5)
        self.assertTrue(r.timed_out)

    def test_run_process_cancel(self):
        import threading
        tok = CancelToken(); threading.Timer(0.3, tok.cancel).start()
        t0 = time.monotonic()
        r = self.a.run_process([sys.executable, "-c", "import time;time.sleep(30)"], cwd=Path.cwd(), env=None, timeout_s=20, cancel=tok)
        self.assertLess(time.monotonic() - t0, 5)
        self.assertTrue(r.cancelled)

    def test_output_is_bounded(self):
        r = self.a.run_process([sys.executable, "-c", "print('x'*5_000_000)"], cwd=Path.cwd(), env=None, timeout_s=20, cancel=CancelToken(),
                               max_output_bytes=2048)
        self.assertLessEqual(len(r.stdout.encode()), 4096)
        self.assertTrue(r.truncated)

    def test_missing_executable_is_reported(self):
        with self.assertRaises(OsalError):
            self.a.run_process(["definitely-not-a-real-binary-xyz"], cwd=Path.cwd(), env=None, timeout_s=5, cancel=CancelToken())

    def test_list_directory(self):
        d = Path(tempfile.mkdtemp())
        (d / "a.txt").write_text("hi"); (d / "sub").mkdir(); (d / ".hidden").write_text("")
        names = [e.name for e in self.a.list_directory(d, show_hidden=False, max_entries=100).entries]
        self.assertEqual(sorted(names), ["a.txt", "sub"])
        names2 = [e.name for e in self.a.list_directory(d, show_hidden=True, max_entries=100).entries]
        self.assertIn(".hidden", names2)
        with self.assertRaises(OsalError):
            self.a.list_directory(d / "nope", show_hidden=False, max_entries=10)

    def test_inventory_marks_deferred_capabilities_unimplemented(self):
        inv = build_inventory(self.a)
        row = inv.capabilities
        for deferred in ("screen.capture", "clipboard", "audio.devices"):
            self.assertFalse(row[deferred].implemented, deferred)
            self.assertEqual(str(getattr(row[deferred].status, "value", row[deferred].status)).lower(), "unavailable")


@linux_only
class LinuxAdapter(unittest.TestCase):
    def setUp(self):
        self.root = Path(tempfile.mkdtemp())
        apps = self.root / "share" / "applications"; apps.mkdir(parents=True)
        (apps / "fakebrowser.desktop").write_text(
            "[Desktop Entry]\nType=Application\nName=Fake Browser\nExec=sleep 20 %U\nCategories=Network;WebBrowser;\n")
        (apps / "hidden.desktop").write_text("[Desktop Entry]\nType=Application\nName=Hidden\nExec=true\nNoDisplay=true\n")
        (apps / "broken.desktop").write_text("[Desktop Entry]\nType=Application\nName=Broken Browser\nExec=/nonexistent/bin/x\nCategories=WebBrowser;\n")
        env = dict(os.environ, HOME=str(self.root), XDG_DATA_HOME=str(self.root / "none"),
                   XDG_DATA_DIRS=str(self.root / "share"))
        self.a = create_adapter(env=env)

    def test_desktop_entries_discovered_and_classified(self):
        apps, _ = self.a.discover_applications()
        by = {a.name: a for a in apps}
        self.assertEqual(by["Fake Browser"].kind, "browser")
        self.assertNotIn("Hidden", by)

    def test_launch_returns_pid_and_process_exists(self):
        apps, _ = self.a.discover_applications()
        app = next(a for a in apps if a.name == "Fake Browser")
        res = self.a.launch_application(app)
        try:
            self.assertIsNotNone(res.pid)
            self.assertTrue(self.a.pid_alive(res.pid))
        finally:
            import signal
            try:
                os.killpg(os.getpgid(res.pid), signal.SIGKILL)
            except OSError:
                pass

    def test_system_executable_resolution_ignores_cwd_and_relative(self):
        self.assertIsNone(self.a.resolve_system_executable("./sh"))
        self.assertIsNone(self.a.resolve_system_executable("../bin/sh"))
        self.assertIsNotNone(self.a.resolve_system_executable("sh"))

    def test_command_environment_is_locale_neutral(self):
        self.assertEqual(self.a.command_environment().get("LC_ALL"), "C")


if __name__ == "__main__":
    unittest.main()
