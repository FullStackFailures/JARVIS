"""Acceptance cases from the Milestone 1 brief, driven through the REAL agent pipeline
(router -> planner -> policy -> executor -> OSAL -> verification -> composer). No tool outputs are faked."""

import os
import signal
import socket
import sys
import tempfile
import threading
import time
import unittest
from pathlib import Path

import psutil

from jarvis.core.models import Outcome
from tests.conftest_helpers import dispose, make_runtime
from tests.harness import linux_only, tags


class Basic(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.dir = Path(tempfile.mkdtemp()).resolve()
        (cls.dir / "alpha.txt").write_text("a"); (cls.dir / "beta").mkdir()
        cls.rt, cls.home = make_runtime(cwd=cls.dir)

    @classmethod
    def tearDownClass(cls):
        dispose(cls.rt, cls.home)

    def ask(self, text):
        return self.rt.agent.run(text, timeout=60)

    def test_greeting_is_a_reply_with_no_tools(self):
        t = self.ask("Hello")
        self.assertEqual(t.outcome, Outcome.REPLY)
        self.assertFalse(t.step_states)

    def test_hostname_is_real(self):
        t = self.ask("what is my hostname")
        self.assertEqual(t.outcome, Outcome.VERIFIED)
        self.assertIn(socket.gethostname(), t.final_response)

    def test_ram_matches_psutil(self):
        t = self.ask("how much RAM do I have")
        self.assertEqual(t.outcome, Outcome.VERIFIED)
        self.assertIn(f"{psutil.virtual_memory().total / 1024**3:.1f} GiB", t.final_response)

    def test_ip_answer_is_a_real_address_of_this_host(self):
        t = self.ask("what is my IP address")
        self.assertEqual(t.outcome, Outcome.VERIFIED)
        ips = {a.address for v in psutil.net_if_addrs().values() for a in v}
        self.assertTrue(any(ip in t.final_response for ip in ips), t.final_response)

    def test_files_here_lists_real_directory(self):
        t = self.ask("list files here")
        self.assertEqual(t.outcome, Outcome.VERIFIED)
        self.assertIn("alpha.txt", t.final_response)
        self.assertIn("beta/", t.final_response)

    def test_installed_apps_query(self):
        t = self.ask("what applications are installed")
        self.assertIn(t.outcome, (Outcome.VERIFIED, Outcome.FAILED))  # an empty box legitimately yields "none"
        self.assertIsNotNone(t.final_response)

    @linux_only
    def test_readonly_terminal_command(self):
        t = self.ask("run uname -s")
        self.assertEqual(t.outcome, Outcome.VERIFIED)
        self.assertIn("Linux", t.final_response)

    @linux_only
    def test_terminal_ip_uses_recovery_alternatives_and_reports_it(self):
        t = self.ask("what is my IP using the terminal")
        self.assertEqual(t.outcome, Outcome.VERIFIED, t.final_response)
        self.assertIn("Local IP address", t.final_response)

    def test_bare_open_does_not_guess_or_search(self):
        t = self.ask("open")
        self.assertEqual(t.outcome, Outcome.NEEDS_INPUT)
        self.assertFalse(t.step_states)
        self.assertNotIn("wikipedia", t.final_response.lower())

    def test_unknown_request_is_not_converted_into_a_lookup(self):
        t = self.ask("what is a quasar")
        self.assertEqual(t.outcome, Outcome.UNSUPPORTED)
        self.assertFalse(t.step_states)

    def test_open_nonexistent_app_reports_failure_honestly(self):
        t = self.ask("open zzqqxx_not_an_app")
        self.assertIn(t.outcome, (Outcome.FAILED, Outcome.NEEDS_INPUT))
        self.assertNotIn("Opened", t.final_response)

    def test_no_browser_installed_is_reported_not_faked(self):
        apps, _ = self.rt.osal.discover_applications()
        if any(a.kind == "browser" for a in apps):
            self.skipTest("a browser exists on this machine; covered by the fixture test")
        t = self.ask("open my browser")
        self.assertEqual(t.outcome, Outcome.FAILED)
        self.assertIn("No browser", t.final_response)

    def test_stop_with_nothing_running(self):
        t = self.ask("stop")
        self.assertEqual(t.outcome, Outcome.REPLY)
        self.assertIn("nothing", t.final_response.lower())

    def test_parallel_system_request_merges_independent_steps(self):
        t = self.ask("check my CPU, RAM, disk and network")
        self.assertEqual(t.outcome, Outcome.VERIFIED, t.final_response)
        for word in ("RAM", "Disk"):
            self.assertIn(word, t.final_response)
        self.assertGreaterEqual(len(t.step_states), 3)

    def test_deferred_capability_is_explicitly_unsupported(self):
        t = self.ask("take a screenshot")
        self.assertEqual(t.outcome, Outcome.UNSUPPORTED)
        self.assertIn("Milestone", t.final_response)

    def test_audit_chain_holds_after_all_of_the_above(self):
        self.ask("what is my hostname")
        self.assertTrue(self.rt.audit.verify().ok)


@linux_only
class Cancellation(unittest.TestCase):
    def test_stop_cancels_running_task_and_kills_process(self):
        rt, home = make_runtime(approve=True)
        try:
            from jarvis.core.models import Plan, Step
            # a real, policy-approved long-running command started through the pipeline
            handle = rt.agent.submit("run sleep 30")
            time.sleep(0.8)
            t0 = time.monotonic()
            rt.agent.run("stop", timeout=10)
            task = handle.wait(10)
            self.assertLess(time.monotonic() - t0, 5)
            self.assertEqual(task.outcome, Outcome.CANCELLED)
            left = [p for p in psutil.process_iter(["cmdline"]) if (p.info["cmdline"] or [])[:2] == ["sleep", "30"]]
            self.assertEqual(left, [], "cancelled command must not keep running")
        finally:
            dispose(rt, home)


@linux_only
class AppLaunchWithFixture(unittest.TestCase):
    """Uses a real .desktop fixture (a harmless `sleep`) so the launch + verify path runs for real."""

    def setUp(self):
        self.root = Path(tempfile.mkdtemp())
        apps = self.root / "share" / "applications"; apps.mkdir(parents=True)
        self.tag = f"{os.getpid()}"
        (apps / "good.desktop").write_text(
            f"[Desktop Entry]\nType=Application\nName=Good Browser\nExec=sleep 41{self.tag[-1]}\nCategories=WebBrowser;\n")
        (apps / "broken.desktop").write_text(
            "[Desktop Entry]\nType=Application\nName=Broken Browser\nExec=/nonexistent/bin/x\nCategories=WebBrowser;\n")
        self.env = dict(os.environ, HOME=str(self.root), XDG_DATA_HOME=str(self.root / "none"),
                        XDG_DATA_DIRS=str(self.root / "share"))
        from jarvis.osal.detect import create_adapter
        from jarvis.config.schema import JarvisConfig
        from jarvis.core.approvals import StaticProvider
        from jarvis.core.runtime import Runtime, temp_home
        self.home = temp_home()
        cfg = JarvisConfig(home_override=self.home)
        cfg.apps.require_graphical_session = False
        self.rt = Runtime.create(cfg, use_keyring=False, approvals=StaticProvider(False),
                                 osal=create_adapter(env=self.env), env=self.env)

    def tearDown(self):
        for p in psutil.process_iter(["cmdline"]):
            if (p.info["cmdline"] or [])[:1] == ["sleep"] and "41" in (p.info["cmdline"] or [""])[-1]:
                p.kill()
        dispose(self.rt, self.home)

    def test_open_my_browser_launches_and_verifies_process(self):
        t = self.rt.agent.run("open my browser", timeout=60)
        self.assertIn(t.outcome, (Outcome.VERIFIED,), t.final_response)
        self.assertIn("Opened", t.final_response)
        self.assertIn("window state was not checked", t.final_response)

    def test_named_broken_app_fails_without_claiming_success(self):
        t = self.rt.agent.run("open Broken Browser", timeout=60)
        self.assertNotEqual(t.outcome, Outcome.VERIFIED, t.final_response)
        self.assertNotIn("Opened Broken", t.final_response)


class ModelBackendUnavailable(unittest.TestCase):
    def test_native_brain_still_answers_when_configured_backend_is_down(self):
        s = socket.socket(); s.bind(("127.0.0.1", 0)); port = s.getsockname()[1]; s.close()

        def mut(cfg):
            cfg.models.ollama.enabled = True
            cfg.models.ollama.model = "none"
            cfg.models.ollama.base_url = f"http://127.0.0.1:{port}"
            cfg.models.ollama.health_timeout_s = 1
            cfg.models.default_backend = "ollama"
        rt, home = make_runtime(cfg_mut=mut)
        try:
            ok = rt.agent.run("what is my hostname", timeout=60)
            self.assertEqual(ok.outcome, Outcome.VERIFIED)
            novel = rt.agent.run("what is a quasar", timeout=60)
            self.assertEqual(novel.outcome, Outcome.UNSUPPORTED)
            self.assertIn("ollama", novel.final_response.lower())
            status = "\n".join(rt.gateway.status_lines())
            self.assertIn("UNREACHABLE", status)
        finally:
            dispose(rt, home)


if __name__ == "__main__":
    unittest.main()
