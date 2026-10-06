"""Executor tests against the REAL executor, policy, audit and thread pool.

The tools registered here (test.*) are small real Tool subclasses; they are test tools, not
doubles of production tools.
"""

import time
import unittest

from jarvis.common.cancel import CancelToken
from jarvis.core.models import Postcondition, FailureClass, PermissionMode as M, RiskLevel, Step, StepStatus, ToolResult
from jarvis.tools._manifest import build_manifest, obj
from jarvis.tools.base import Tool, ToolFailure, ToolOutput
from tests.conftest_helpers import dispose, make_runtime
from tests.harness import tags


def pc(path):
    return Postcondition(kind="field_present", path=path)


class Sleeper(Tool):
    manifest = build_manifest("test.sleep", "Sleeps cooperatively until cancelled or finished.",
                              obj({"seconds": {"type": "number"}}, ["seconds"]), obj({"slept": {"type": "number"}}, ["slept"]),
                              permissions=["system.read"], timeout_ms=400, cancellable=True, postcondition=pc("data.slept"))

    def execute(self, args, ctx):
        end = time.monotonic() + args["seconds"]
        while time.monotonic() < end:
            if ctx.cancel.wait(0.01):
                raise ToolFailure(FailureClass.CANCELLED, "cancelled")
        return ToolOutput({"slept": args["seconds"]}, method="test")


class BadOutput(Tool):
    manifest = build_manifest("test.bad_output", "Returns data violating its own output schema.",
                              obj({}), obj({"n": {"type": "integer"}}, ["n"]), permissions=["system.read"], postcondition=pc("data.n"))

    def execute(self, args, ctx):
        return ToolOutput({"n": "not-an-int"}, method="test")


class Flaky(Tool):
    calls = 0
    manifest = build_manifest("test.flaky", "Fails retryably twice then succeeds.", obj({}),
                              obj({"calls": {"type": "integer"}}, ["calls"]), permissions=["system.read"], postcondition=pc("data.calls"))

    def execute(self, args, ctx):
        Flaky.calls += 1
        if Flaky.calls < 3:
            raise ToolFailure(FailureClass.TOOL_ERROR, "transient", retryable=True)
        return ToolOutput({"calls": Flaky.calls}, method="test")


class Source(Tool):
    manifest = build_manifest("test.source", "Produces a value for reference resolution.", obj({}),
                              obj({"value": {"type": "string"}}, ["value"]), permissions=["system.read"], postcondition=pc("data.value"))

    def execute(self, args, ctx):
        return ToolOutput({"value": "hello"}, method="test")


class Echo(Tool):
    manifest = build_manifest("test.echo", "Echoes its text argument back.", obj({"text": {"type": "string"}}, ["text"]),
                              obj({"text": {"type": "string"}}, ["text"]), permissions=["system.read"], postcondition=pc("data.text"))

    def execute(self, args, ctx):
        return ToolOutput({"text": args["text"]}, method="test")


class ExecutorTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.rt, cls.home = make_runtime(extra_tools=[Sleeper, BadOutput, Flaky, Source, Echo])

    @classmethod
    def tearDownClass(cls):
        dispose(cls.rt, cls.home)

    def run_step(self, tool, args, mode=M.NORMAL, cancel=None, results=None, sid="s1"):
        step = Step(id=sid, tool=tool, arguments=args)
        return self.rt.executor.run_step(step, task_id="task_test", results=results or {},
                                         cancel=cancel or CancelToken(), mode=mode)

    def test_malformed_arguments_rejected_before_execution(self):
        for args in ({}, {"seconds": "abc"}, {"seconds": 1, "bogus": 1}):
            r = self.run_step("test.sleep", args)
            self.assertFalse(r.result.ok)
            self.assertEqual(r.result.failure_class, FailureClass.INVALID_ARGUMENTS, args)
            self.assertEqual(r.status, StepStatus.FAILED)

    def test_unknown_tool(self):
        r = self.run_step("nope.nothing", {})
        self.assertEqual(r.result.failure_class, FailureClass.UNKNOWN_TOOL)

    def test_timeout_enforced(self):
        t0 = time.monotonic()
        r = self.run_step("test.sleep", {"seconds": 30})
        self.assertLess(time.monotonic() - t0, 5)
        self.assertEqual(r.result.failure_class, FailureClass.TIMEOUT)

    def test_cancellation_stops_running_tool(self):
        tok = CancelToken()
        import threading
        threading.Timer(0.1, tok.cancel).start()
        t0 = time.monotonic()
        r = self.run_step("test.sleep", {"seconds": 30}, cancel=tok)
        self.assertLess(time.monotonic() - t0, 2)
        self.assertFalse(r.result.ok)
        self.assertIn(r.result.failure_class, (FailureClass.CANCELLED, FailureClass.TIMEOUT))

    def test_output_contract_violation_detected(self):
        r = self.run_step("test.bad_output", {})
        self.assertFalse(r.result.ok)
        self.assertEqual(r.result.failure_class, FailureClass.CONTRACT_VIOLATION)

    def test_retryable_failures_are_retried(self):
        # default policy: one mechanical retry -> exactly 2 attempts, then the failure is reported
        Flaky.calls = 0
        r = self.run_step("test.flaky", {})
        self.assertFalse(r.result.ok)
        self.assertEqual(len(r.attempts), 2)
        # raising the bound lets the third attempt succeed
        self.rt.config.limits.mechanical_retries = 2
        try:
            Flaky.calls = 0
            r = self.run_step("test.flaky", {})
            self.assertTrue(r.result.ok, r.result.error)
            self.assertEqual(len(r.attempts), 3)
        finally:
            self.rt.config.limits.mechanical_retries = 1

    def test_reference_resolution(self):
        src = self.run_step("test.source", {}, sid="s1")
        res = {"s1": src.result}
        r = self.run_step("test.echo", {"text": "${s1.data.value}"}, results=res, sid="s2")
        self.assertTrue(r.result.ok, r.result.error)
        self.assertEqual(r.result.data["text"], "hello")

    def test_reference_to_failed_step_is_skipped_not_run(self):
        bad = self.run_step("test.bad_output", {}, sid="s1")
        r = self.run_step("test.echo", {"text": "${s1.data.n}"}, results={"s1": bad.result}, sid="s2")
        self.assertFalse(r.result.ok)
        self.assertEqual(r.status, StepStatus.SKIPPED)

    @unittest.skipUnless(__import__("sys").platform.startswith("linux"), "uses POSIX sleep")
    @tags("LINUX")
    def test_policy_denial_never_reaches_tool(self):
        r = self.run_step("terminal.execute", {"argv": ["rm", "-rf", "/tmp/jarvis_should_never_run"]})
        self.assertFalse(r.result.ok)
        self.assertEqual(r.result.failure_class, FailureClass.POLICY_DENIED)
        self.assertEqual(r.policy.decision.value, "DENY")

    @unittest.skipUnless(__import__("sys").platform.startswith("linux"), "uses POSIX tools")
    @tags("LINUX")
    def test_ask_is_declined_without_approver(self):
        r = self.run_step("terminal.execute", {"argv": ["some-unknown-binary-xyz"]})
        self.assertFalse(r.result.ok)
        self.assertEqual(r.result.failure_class, FailureClass.POLICY_DENIED)

    def test_restricted_mode_denies_launch(self):
        r = self.run_step("apps.open", {"app_id": "anything"}, mode=M.RESTRICTED)
        self.assertEqual(r.result.failure_class, FailureClass.POLICY_DENIED)

    def test_audit_records_each_step_and_chain_intact(self):
        before = self.rt.audit.count()
        self.run_step("test.echo", {"text": "x"})
        self.assertGreater(self.rt.audit.count(), before)
        self.assertTrue(self.rt.audit.verify().ok)


class AuditFailClosed(unittest.TestCase):
    def test_step_not_executed_when_audit_write_fails(self):
        rt, home = make_runtime(extra_tools=[Echo])
        try:
            ran = []

            class Spy(Tool):
                manifest = build_manifest("test.spy", "Records that it ran, to prove it did not.", obj({}),
                                          obj({}, [], True), permissions=["system.read"], postcondition=pc("platform"))

                def execute(self, args, ctx):
                    ran.append(1)
                    return ToolOutput({}, method="test")

            rt.registry.register(Spy)
            rt.audit.close()  # every later append raises
            r = rt.executor.run_step(Step(id="s1", tool="test.spy"), task_id="t", results={},
                                     cancel=CancelToken(), mode=M.NORMAL)
            self.assertFalse(r.result.ok)
            self.assertEqual(ran, [])
        finally:
            import shutil
            shutil.rmtree(home, ignore_errors=True)


if __name__ == "__main__":
    unittest.main()
