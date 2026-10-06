"""Step executor: validate -> policy -> (approval) -> locks -> run -> contract check -> verify.

A step is never run without a PolicyDecision, and never run if the audit log cannot record
that it is about to run (fail closed).
"""

from __future__ import annotations

import logging
import re
import threading
import time
from collections.abc import Mapping
from concurrent.futures import Future, ThreadPoolExecutor
from concurrent.futures import TimeoutError as FutureTimeout
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from jsonschema import Draft202012Validator

from jarvis.common.cancel import CancelToken
from jarvis.common.util import now
from jarvis.config.schema import JarvisConfig
from jarvis.core import verification
from jarvis.core.approvals import ApprovalProvider
from jarvis.core.events import EventBus
from jarvis.core.locks import ResourceBusy, ResourceLocks
from jarvis.core.models import (
    ApprovalRequest,
    ApprovalResponse,
    AttemptRecord,
    Decision,
    EntityHint,
    FailureClass,
    PermissionMode,
    PolicyDecision,
    Postcondition,
    Step,
    StepStatus,
    Taint,
    ToolError,
    ToolResult,
)
from jarvis.osal.base import OSAdapter
from jarvis.osal.types import CapabilityInventory
from jarvis.policy.engine import PolicyEngine, PolicyRequest
from jarvis.registry.registry import ToolRegistry
from jarvis.security.audit import AuditError, AuditLog
from jarvis.security.redact import REDACTOR
from jarvis.tools.base import Tool, ToolContext, ToolFailure, ToolOutput

log = logging.getLogger(__name__)

_REF = re.compile(r"^\$\{(s[0-9]+)\.([A-Za-z0-9_.]+)\}$")


@dataclass
class StepRun:
    step_id: str
    tool: str
    result: ToolResult
    status: StepStatus
    policy: PolicyDecision | None = None
    approval: ApprovalResponse | None = None
    attempts: list[AttemptRecord] = field(default_factory=list)
    entities: list[EntityHint] = field(default_factory=list)
    resolved_arguments: dict[str, Any] = field(default_factory=dict)


class ReferenceError_(Exception):
    def __init__(self, cls: FailureClass, message: str) -> None:
        super().__init__(message)
        self.cls = cls
        self.message = message


def usable(result: ToolResult | None) -> bool:
    return result is not None and result.ok and result.verified is not False


def resolve_references(
    value: Any, results: Mapping[str, ToolResult], sources: set[str]
) -> Any:
    """Replace exact "${sN.path}" strings with upstream values; record the source steps."""
    if isinstance(value, str):
        m = _REF.match(value)
        if not m:
            return value
        sid, path = m.group(1), m.group(2)
        upstream = results.get(sid)
        if upstream is None:
            raise ReferenceError_(FailureClass.DEPENDENCY_FAILED, f"step {sid} has no result")
        if not usable(upstream):
            raise ReferenceError_(FailureClass.DEPENDENCY_FAILED, f"step {sid} did not succeed")
        found = verification.lookup(upstream, path)
        if found is verification._MISSING or found is None or found == "":
            raise ReferenceError_(
                FailureClass.UNAVAILABLE, f"step {sid} produced no value for {path!r}"
            )
        sources.add(sid)
        return found
    if isinstance(value, dict):
        return {k: resolve_references(v, results, sources) for k, v in value.items()}
    if isinstance(value, list):
        return [resolve_references(v, results, sources) for v in value]
    return value


class Executor:
    def __init__(
        self,
        *,
        registry: ToolRegistry,
        policy: PolicyEngine,
        osal: OSAdapter,
        inventory: CapabilityInventory,
        config: JarvisConfig,
        audit: AuditLog,
        approvals: ApprovalProvider,
        locks: ResourceLocks,
        events: EventBus,
        cwd: Path,
        notes_dir: Path | None = None,
    ) -> None:
        self.registry = registry
        self.policy = policy
        self.osal = osal
        self.inventory = inventory
        self.config = config
        self.audit = audit
        self.approvals = approvals
        self.locks = locks
        self.events = events
        self.cwd = cwd
        self.notes_dir = notes_dir
        self._pool = ThreadPoolExecutor(
            max_workers=max(4, config.limits.max_parallel * 2), thread_name_prefix="jarvis-tool"
        )
        self._validators: dict[str, tuple[Draft202012Validator, Draft202012Validator]] = {}
        self._vlock = threading.Lock()

    def shutdown(self) -> None:
        self._pool.shutdown(wait=False, cancel_futures=True)

    # ------------------------------------------------------------------ helpers
    def _validators_for(self, tool: Tool) -> tuple[Draft202012Validator, Draft202012Validator]:
        with self._vlock:
            v = self._validators.get(tool.manifest.name)
            if v is None:
                v = (
                    Draft202012Validator(tool.manifest.input_schema),
                    Draft202012Validator(tool.manifest.output_schema),
                )
                self._validators[tool.manifest.name] = v
            return v

    @staticmethod
    def _problems(validator: Draft202012Validator, instance: Any, limit: int = 3) -> list[str]:
        out = []
        for e in sorted(validator.iter_errors(instance), key=lambda e: list(map(str, e.path)))[:limit]:
            loc = ".".join(str(p) for p in e.path) or "(root)"
            out.append(f"{loc}: {e.message}")
        return out

    def _fail(
        self,
        step: Step,
        cls: FailureClass,
        message: str,
        *,
        started: float,
        status: StepStatus = StepStatus.FAILED,
        policy: PolicyDecision | None = None,
        approval: ApprovalResponse | None = None,
        data: dict[str, Any] | None = None,
        retryable: bool = False,
        args: dict[str, Any] | None = None,
        taint: Taint = Taint.TRUSTED,
    ) -> StepRun:
        result = ToolResult(
            ok=False, tool=step.tool, step_id=step.id, platform=self.osal.name,
            data=data or {}, error=ToolError(cls=cls, message=REDACTOR.scrub_text(message), retryable=retryable),
            duration_ms=int((time.monotonic() - started) * 1000), taint=taint,
        )
        return StepRun(step.id, step.tool, result, status, policy, approval,
                       [AttemptRecord(tool=step.tool, arguments=args or step.arguments, ok=False,
                                      failure=cls.value, duration_ms=result.duration_ms)],
                       resolved_arguments=args or {})

    def _audit(self, kind: str, task_id: str, **payload: Any) -> None:
        self.audit.append(kind, task_id, **payload)

    # ------------------------------------------------------------------ main entry
    def run_step(
        self,
        step: Step,
        *,
        task_id: str,
        results: Mapping[str, ToolResult],
        cancel: CancelToken,
        mode: PermissionMode,
    ) -> StepRun:
        started = time.monotonic()
        tool = self.registry.get(step.tool)
        if tool is None:
            return self._fail(step, FailureClass.UNKNOWN_TOOL, f"unknown tool {step.tool!r}", started=started)
        avail = self.registry.availability(step.tool, self.osal.name, self.inventory)
        if not avail.available:
            return self._fail(step, FailureClass.UNAVAILABLE, f"{step.tool} unavailable: {avail.reason}",
                              started=started)

        sources: set[str] = set()
        try:
            args = resolve_references(step.arguments, results, sources)
        except ReferenceError_ as exc:
            return self._fail(step, exc.cls, exc.message, started=started, status=StepStatus.SKIPPED
                              if exc.cls == FailureClass.DEPENDENCY_FAILED else StepStatus.FAILED)
        tainted = any(results[s].taint == Taint.UNTRUSTED for s in sources)

        in_v, out_v = self._validators_for(tool)
        problems = self._problems(in_v, args)
        if problems:
            return self._fail(step, FailureClass.INVALID_ARGUMENTS,
                              "invalid arguments: " + "; ".join(problems), started=started, args=args)

        try:
            decision = self.policy.evaluate(
                PolicyRequest(manifest=tool.manifest, arguments=args, mode=mode, tainted=tainted, cwd=self.cwd)
            )
        except Exception as exc:  # fail closed: a broken policy engine must never mean "allowed"
            log.exception("policy evaluation crashed for %s", step.tool)
            return self._fail(step, FailureClass.POLICY_DENIED,
                              f"denied: policy evaluation failed ({type(exc).__name__}); refusing to execute",
                              started=started, args=args)
        if not isinstance(decision, PolicyDecision):
            return self._fail(step, FailureClass.POLICY_DENIED,
                              "denied: policy returned no decision; refusing to execute", started=started, args=args)
        try:
            self._audit("policy.decision", task_id, step_id=step.id, tool=step.tool, arguments=args,
                        decision=decision.decision.value, risk=decision.risk.value,
                        reasons=decision.reasons, tainted=tainted, permission_mode=mode.value)
        except AuditError as exc:
            return self._fail(step, FailureClass.INTERNAL,
                              f"audit log unavailable, refusing to execute: {exc}", started=started,
                              policy=decision, args=args)

        approval: ApprovalResponse | None = None
        if decision.decision == Decision.DENY:
            return self._fail(step, FailureClass.POLICY_DENIED, "denied by policy: " + "; ".join(decision.reasons),
                              started=started, policy=decision, args=args)
        if decision.decision == Decision.ASK:
            req = ApprovalRequest(task_id=task_id, step_id=step.id, tool=step.tool, arguments=args,
                                  risk=decision.risk, reasons=decision.reasons)
            try:
                self._audit("approval.requested", task_id, request_id=req.id, tool=step.tool,
                            arguments=args, risk=decision.risk.value, reasons=decision.reasons)
            except AuditError as exc:
                return self._fail(step, FailureClass.INTERNAL, f"audit log unavailable: {exc}",
                                  started=started, policy=decision, args=args)
            approval = self.approvals.request(req)
            try:
                self._audit("approval.decided", task_id, request_id=req.id, approved=approval.approved,
                            note=approval.note)
            except AuditError:
                log.error("audit write failed for approval decision")
            if not approval.approved:
                return self._fail(step, FailureClass.POLICY_DENIED,
                                  f"approval required and not granted ({approval.note})", started=started,
                                  policy=decision, approval=approval, args=args)

        if cancel.is_set():
            return self._fail(step, FailureClass.CANCELLED, "cancelled before execution", started=started,
                              status=StepStatus.CANCELLED, policy=decision, approval=approval, args=args)

        try:
            held = self.locks.acquire(tool.manifest.resources, self.config.limits.lock_timeout_s, cancel)
        except ResourceBusy as exc:
            return self._fail(step, FailureClass.RESOURCE_BUSY, str(exc), started=started,
                              policy=decision, approval=approval, args=args)
        try:
            return self._execute_with_retries(tool, step, args, tainted, decision, approval,
                                              task_id, cancel, out_v, started)
        finally:
            self.locks.release(held)

    # ------------------------------------------------------------------ execution
    def _execute_with_retries(
        self, tool: Tool, step: Step, args: dict[str, Any], tainted: bool,
        decision: PolicyDecision, approval: ApprovalResponse | None, task_id: str,
        cancel: CancelToken, out_v: Draft202012Validator, started: float,
    ) -> StepRun:
        attempts: list[AttemptRecord] = []
        max_attempts = 1 + (self.config.limits.mechanical_retries if tool.manifest.idempotent else 0)
        run: StepRun | None = None
        for n in range(1, max_attempts + 1):
            try:
                self._audit("tool.started", task_id, step_id=step.id, tool=step.tool, arguments=args,
                            attempt=n, permission_mode=decision.mode.value)
            except AuditError as exc:
                return self._fail(step, FailureClass.INTERNAL,
                                  f"audit log unavailable, refusing to execute: {exc}", started=started,
                                  policy=decision, approval=approval, args=args)
            run = self._execute_once(tool, step, args, tainted, task_id, cancel, out_v)
            run.policy, run.approval = decision, approval
            res = run.result
            res.attempts = n
            attempts.append(AttemptRecord(tool=step.tool, arguments=args, ok=res.ok and res.verified is not False,
                                          failure=res.error.cls.value if res.error else None,
                                          duration_ms=res.duration_ms))
            try:
                self._audit("tool.result", task_id, step_id=step.id, tool=step.tool, ok=res.ok,
                            verified=res.verified, verification_note=res.verification_note,
                            error=res.error.model_dump(mode="json") if res.error else None,
                            duration_ms=res.duration_ms, attempt=n)
            except AuditError:
                log.error("audit write failed for tool result")
                res.verification_note = (res.verification_note or "") + " [audit write failed]"
            retryable = res.error is not None and res.error.retryable
            if res.ok or not retryable or cancel.is_set() or n == max_attempts:
                break
            self.events.publish("tool.retry", task_id=task_id, step_id=step.id, tool=step.tool, attempt=n)
        assert run is not None
        run.attempts = attempts
        run.resolved_arguments = args
        res = run.result
        res.duration_ms = int((time.monotonic() - started) * 1000)
        return run

    def _execute_once(
        self, tool: Tool, step: Step, args: dict[str, Any], tainted: bool, task_id: str,
        cancel: CancelToken, out_v: Draft202012Validator,
    ) -> StepRun:
        t0 = time.monotonic()
        step_cancel = cancel.child()
        tctx = ToolContext(
            osal=self.osal, config=self.config, inventory=self.inventory, cancel=step_cancel,
            cwd=self.cwd, task_id=task_id, step_id=step.id, notes_dir=self.notes_dir,
        )
        timeout_s = tool.effective_timeout_ms(args) / 1000.0
        started_at = now()
        outcome = self._run_in_pool(tool, args, tctx, timeout_s, cancel, step_cancel)

        def finish(**kw: Any) -> ToolResult:
            return ToolResult(tool=step.tool, step_id=step.id, platform=self.osal.name,
                              duration_ms=int((time.monotonic() - t0) * 1000), started_at=started_at, **kw)

        if isinstance(outcome, ToolFailure):
            err_taint = Taint.UNTRUSTED if tainted else Taint.TRUSTED
            res = finish(ok=False, data=outcome.data, taint=err_taint,
                         error=ToolError(cls=outcome.cls, message=REDACTOR.scrub_text(outcome.message),
                                         retryable=outcome.retryable))
            status = StepStatus.CANCELLED if outcome.cls == FailureClass.CANCELLED else StepStatus.FAILED
            return StepRun(step.id, step.tool, res, status, attempts=[])

        output: ToolOutput = outcome
        taint = output.taint or tool.manifest.result_taint
        if tainted:
            taint = Taint.UNTRUSTED  # taint propagates through data flow
        problems = self._problems(out_v, output.data)
        if problems:
            res = finish(ok=False, taint=taint, error=ToolError(
                cls=FailureClass.CONTRACT_VIOLATION,
                message="tool output violates its output_schema: " + "; ".join(problems)))
            return StepRun(step.id, step.tool, res, StepStatus.FAILED)

        result = finish(ok=True, data=output.data, method_used=output.method, taint=taint)
        verified, note = self._verify(tool, step, args, output, result, tctx)
        result.data = output.data
        result.verified, result.verification_note = verified, note
        if verified is False:
            result.error = ToolError(cls=FailureClass.VERIFICATION_FAILED, message=note or "verification failed")
            status = StepStatus.FAILED
        elif verified is True:
            status = StepStatus.VERIFIED
        else:
            status = StepStatus.EXECUTED
        return StepRun(step.id, step.tool, result, status, entities=output.entities)

    def _verify(
        self, tool: Tool, step: Step, args: dict[str, Any], output: ToolOutput,
        result: ToolResult, tctx: ToolContext,
    ) -> tuple[bool | None, str]:
        pcs: list[Postcondition] = []
        if tool.manifest.postcondition:
            pcs.append(tool.manifest.postcondition)
        if step.postcondition:
            pcs.append(step.postcondition)
        verdicts: list[bool | None] = []
        notes: list[str] = []
        for pc in pcs:
            if pc.kind == "tool_verified":
                try:
                    v = tool.verify(args, output, tctx)
                except Exception as exc:
                    log.exception("tool verify crashed: %s", tool.manifest.name)
                    verdicts.append(False)
                    notes.append(f"verification crashed: {type(exc).__name__}")
                    continue
                if v is None:
                    verdicts.append(None)
                    notes.append("tool provides no verification")
                else:
                    if v.data_update:
                        output.data.update(v.data_update)
                        result.data = output.data
                    verdicts.append(v.verified)
                    notes.append(v.note)
            else:
                ok, note = verification.evaluate(pc, result)
                verdicts.append(ok)
                notes.append(note)
        if not verdicts:
            return None, "no postcondition declared"
        if any(v is False for v in verdicts):
            bad = next(n for v, n in zip(verdicts, notes, strict=True) if v is False)
            return False, bad
        if all(v is True for v in verdicts):
            return True, "; ".join(n for n in notes if n)
        return None, "; ".join(n for n in notes if n)

    def _run_in_pool(
        self, tool: Tool, args: dict[str, Any], tctx: ToolContext, timeout_s: float,
        cancel: CancelToken, step_cancel: CancelToken,
    ) -> ToolOutput | ToolFailure:
        fut: Future[ToolOutput] = self._pool.submit(tool.execute, args, tctx)
        deadline = time.monotonic() + timeout_s
        grace = self.config.limits.executor_grace_s

        def collect(f: Future[ToolOutput]) -> ToolOutput | ToolFailure:
            try:
                return f.result(timeout=0)
            except ToolFailure as tf:
                return tf
            except Exception as exc:
                log.exception("tool %s crashed", tool.manifest.name)
                return ToolFailure(FailureClass.INTERNAL, f"{type(exc).__name__}: {exc}")

        while True:
            try:
                fut.result(timeout=0.02)
                return collect(fut)
            except FutureTimeout:
                if fut.done():  # the tool itself raised a TimeoutError
                    return collect(fut)
            except Exception:
                return collect(fut)
            if cancel.is_set():
                end = time.monotonic() + grace
                while time.monotonic() < end and not fut.done():
                    time.sleep(0.01)
                if fut.done():
                    res = collect(fut)
                    if isinstance(res, ToolFailure):
                        return res
                    return ToolFailure(FailureClass.CANCELLED, "cancelled")
                return ToolFailure(FailureClass.CANCELLED, "cancelled; the tool did not stop in time")
            if time.monotonic() >= deadline:
                step_cancel.cancel("timeout")
                end = time.monotonic() + grace
                while time.monotonic() < end and not fut.done():
                    time.sleep(0.01)
                if fut.done():
                    res = collect(fut)
                    if isinstance(res, ToolFailure) and res.cls == FailureClass.TIMEOUT:
                        return res
                return ToolFailure(
                    FailureClass.TIMEOUT,
                    f"{tool.manifest.name} exceeded {timeout_s:.1f}s and was abandoned",
                    retryable=tool.manifest.idempotent,
                )
