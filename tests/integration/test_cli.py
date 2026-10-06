"""CLI exercised as a real subprocess with an isolated JARVIS_HOME."""

import json
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]


def jarvis(*args, home):
    env = dict(os.environ, PYTHONPATH=str(ROOT / "src"), JARVIS_HOME=home)
    return subprocess.run([sys.executable, "-m", "jarvis", *args], capture_output=True, text=True, env=env,
                          timeout=120, cwd=str(ROOT), stdin=subprocess.DEVNULL)


class Cli(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.home = tempfile.mkdtemp()

    def test_version(self):
        r = jarvis("--version", home=self.home)
        self.assertEqual(r.returncode, 0)
        self.assertTrue(r.stdout.startswith("jarvis "))

    def test_self_test_passes_and_names_real_platform(self):
        r = jarvis("--self-test", home=self.home)
        self.assertEqual(r.returncode, 0, r.stdout + r.stderr)
        self.assertIn("0 failed", r.stdout)
        self.assertIn("platform: " + ("windows" if sys.platform == "win32" else "linux"), r.stdout)

    def test_doctor_reports_backends_and_contracts(self):
        r = jarvis("--doctor", home=self.home)
        self.assertEqual(r.returncode, 0, r.stderr)
        for needle in ("Capability inventory", "JARVIS Brain: ACTIVE", "manifest contract violations: 0"):
            self.assertIn(needle, r.stdout)

    def test_status_tools_tasks_logs_audit(self):
        for flag in (["--status"], ["--tools"], ["--tasks"], ["--logs", "3"]):
            r = jarvis(*flag, home=self.home)
            self.assertEqual(r.returncode, 0, (flag, r.stderr))
        self.assertIn("audit chain OK", jarvis("--audit-verify", home=self.home).stdout)

    def test_one_shot_request_and_json_output(self):
        r = jarvis("--json", "what is my hostname", home=self.home)
        self.assertEqual(r.returncode, 0, r.stderr)
        data = json.loads(r.stdout)
        self.assertEqual(data["outcome"], "VERIFIED")

    def test_unknown_request_exit_code_is_nonzero_not_a_guess(self):
        r = jarvis("what is a quasar", home=self.home)
        self.assertNotEqual(r.returncode, 0)

    def test_noninteractive_approval_fails_closed(self):
        if not sys.platform.startswith("linux"):
            self.skipTest("uses POSIX command")
        r = jarvis("run some-unknown-binary-xyz", home=self.home)
        self.assertNotEqual(r.returncode, 0)


if __name__ == "__main__":
    unittest.main()
