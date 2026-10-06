"""The Agent: one pipeline for every request, whether typed now or spoken later.

submit -> classify/route -> context -> plan -> validate -> policy+execute (per step) ->
observe -> verify -> ledger -> response
"""

from __future__ import annotations

import logging
import re
import threading
import time
from collections.abc import Callable
from concurrent.futures import ThreadPoolExecutor
from typing import Any

from jarvis.brain import composer
from jarvis.brain.recovery import RecoveryEngine
from jarvis.brain.router import Router, Routed
from jarvis.brain.templates import RouteContext
from jarvis.common.cancel import CancelToken
from jarvis.common.util import now
from jarvis.config.schema import JarvisConfig
from jarvis.core.context import ContextManager
from jarvis.core.events import EventBus
from jarvis.core.executor import Executor, StepRun
from jarvis.core.models import (
    ExecMode,
    LedgerEntry,
    Outcome,
    PermissionMode,
    RequestClass,
    RiskLevel,
    Step,
    StepState,
    StepStatus,
    Task,
    TaskStatus,
    ToolResult,
    Utterance,
)
from jarvis.core.planner import Planner, add_implicit_dependencies
from jarvis.core.task_manager import TaskManager
from jarvis.models.gateway import ModelGateway
from jarvis.osal.base import OSAdapter
from jarvis.osal.types import CapabilityInventory
from jarvis.registry.registry import ToolRegistry
from jarvis.security.audit import AuditError, AuditLog

log = logging.getLogger(__name__)

_CONTROL = re.compile(
    r"^(?:please\s+)?(?:stop|cancel|abort|halt|never\s?mind|stop that|cancel that|stop it|cancel it|"
    r"stop everything|(?:cancel|stop|abort) (?:the )?(?:current )?task)[\s.!]*$",
    re.IGNORECASE,
)
_FAILED_SET = {StepStatus.FAILED, StepStatus.SKIPPED, StepStatus.CANCELLED}
_DONE_OK = {StepStatus.VERIFIED, StepStatus.EXECUTED}


class TaskHandle:
    def __init__(self, task: Task, cancel: CancelToken, control: bool = False) -> None:
        self.task = task
        self.cancel_token = cancel
        self.control = control
        self._done = threading.Event()

    def wait(self, timeout: float | None = None) -> Task:
        self._done.wait(timeout)
        return self.task

    @property
    def done(self) -> bool:
        return self._done.is_set()

    def cancel(self, reason: str = "cancelled by user") -> None:
        self.cancel_token.cancel(reason)


class Agent:
    def __init__(
        self,
        *,
        config: JarvisConfig,
        osal: OSAdapter,
        inventory: CapabilityInventory,
        registry: ToolRegistry,
        executor: Executor,
        router: Router,
        planner: Planner,
        recovery: RecoveryEngine,
        context: ContextManager,
        gateway: ModelGateway,
        audit: AuditLog,
        tasks: TaskManager,
        events: EventBus,
        mode: PermissionMode,
    ) -> None:
        self.config = config
        self.osal = osal
        self.inventory = inventory
        self.registry = registry
        self.executor = executor
        self.router = router
        self.planner = planner
        self.recovery = recovery
        self.ctx = context
        self.gateway = gateway
        self.audit = audit
        self.tasks = tasks
        self.events = events
        self.mode = mode
        self._handles: dict[str, TaskHandle] = {}
        self._hlock = threading.Lock()
        self._coord = ThreadPoolExecutor(max_workers=max(2, config.limits.max_parallel),
                                         thread_name_prefix="jarvis-step")
        self._last_finished: Task | None = None

    # ------------------------------------------------------------------ public API
    def submit(self, utterance: str | Utterance, source: str = "text",
               on_created: Callable[[Task], None] | None = None) -> TaskHandle:
        utt = utterance if isinstance(utterance, Utterance) else Utterance(text=utterance, source=source)  # type: ignore[arg-type]
        task = self.tasks.create(utt.text, utt.source, self.mode, self.gateway.default)
        if on_created is not None:
            on_created(task)  # lets a front-end bind the task id before any step can ask for approval
        cancel = CancelToken()
        control = bool(_CONTROL.match(utt.text))
        handle = TaskHandle(task, cancel, control)
        with self._hlock:
            self._handles[task.id] = handle
        if control:
            try:
                self._run_control(task, handle)
            except Exception as exc:
                log.exception("control task failed")
                handle._done.set()
                task.final_response = f"Stop handling failed internally: {type(exc).__name__}"
                task.outcome, task.status = Outcome.FAILED, TaskStatus.FAILED
            return handle
        t = threading.Thread(target=self._process_safe, args=(task, handle), name=f"jarvis-{task.id}", daemon=True)
        t.start()
        return handle

    def run(self, text: str, timeout: float | None = 180.0) -> Task:
        return self.submit(text).wait(timeout)

    def cancel_all(self, reason: str = "cancelled by user") -> int:
        n = 0
        with self._hlock:
            handles = [h for h in self._handles.values() if not h.control and not h.done]
        for h in handles:
            h.cancel(reason)
            n += 1
        return n

    def shutdown(self) -> None:
        self.cancel_all("shutdown")
        self._coord.shutdown(wait=False, cancel_futures=True)

    # ------------------------------------------------------------------ control path
    def _run_control(self, task: Task, handle: TaskHandle) -> None:
        task.request_class = RequestClass.CONTROL
        self._audit("task.submitted", task, request=task.goal, source=task.source, control=True,
                    permission_mode=self.mode.value)
        with self._hlock:
            targets = [h for h in self._handles.values() if not h.control and not h.done]
        for h in targets:
            h.cancel("user asked to stop")
        deadline = time.monotonic() + 3.0
        for h in targets:
            h.wait(max(0.0, deadline - time.monotonic()))
        if not targets:
            text, outcome = "There is nothing running to stop.", Outcome.REPLY
        elif all(h.done for h in targets):
            text = "Stopped: " + "; ".join(f"\"{h.task.goal}\"" for h in targets)
            outcome = Outcome.VERIFIED
        else:
            text = "Stop requested; some work is still shutting down."
            outcome = Outcome.PARTIAL
        self._finish(task, handle, text, outcome, TaskStatus.COMPLETED if outcome != Outcome.PARTIAL
                     else TaskStatus.PARTIALLY_COMPLETED)

    # ------------------------------------------------------------------ main pipeline
    def _process_safe(self, task: Task, handle: TaskHandle) -> None:
        try:
            self._process(task, handle)
        except Exception as exc:  # the runtime must never die on one bad task
            log.exception("task %s crashed", task.id)
            task.failures.append(f"internal error: {type(exc).__name__}")
            try:
                self._finish(task, handle, f"I could not do that: internal error ({type(exc).__name__}: {exc}).",
                             Outcome.FAILED, TaskStatus.FAILED)
            except Exception:
                handle._done.set()

    def _process(self, task: Task, handle: TaskHandle) -> None:
        cancel = handle.cancel_token
        task.status = TaskStatus.PLANNING
        self._audit("task.submitted", task, request=task.goal, source=task.source,
                    permission_mode=self.mode.value, backend=self.gateway.default)
        self.events.publish("task.submitted", task_id=task.id)
        packet = self.ctx.packet(task)
        rc = RouteContext(self.ctx, self.osal, self.inventory, [])
        routed = self.router.route(task.goal, rc)
        task.request_class = routed.request_class
        task.route = routed.summary()
        self._audit("task.routed", task, route=task.route, unhandled=routed.unhandled)

        if routed.kind == "reply":
            text = composer.render_reply(routed.reply_kind or "", packet, self._state())
            self._finish(task, handle, text, Outcome.REPLY, TaskStatus.COMPLETED)
            return
        if routed.kind == "clarify":
            self._finish(task, handle, routed.text or "Could you clarify?", Outcome.NEEDS_INPUT, TaskStatus.WAITING)
            return
        if routed.kind == "unsupported":
            self._finish(task, handle, routed.text or "Not supported yet.", Outcome.UNSUPPORTED, TaskStatus.FAILED)
            return

        if routed.kind == "unknown":
            plan_result = self.planner.plan_with_reasoner(task.goal, packet, task.id)
            if plan_result.kind == "plan" and plan_result.plan is not None:
                task.backend_used = plan_result.backend
                routed = Routed("plan", RequestClass.UNKNOWN, [f"reasoner:{plan_result.backend}"], 0.5,
                                plan=plan_result.plan)
            elif plan_result.kind in {"reply", "clarify"}:
                task.backend_used = plan_result.backend
                self._finish(task, handle, plan_result.text, Outcome.REPLY if plan_result.kind == "reply"
                             else Outcome.NEEDS_INPUT,
                             TaskStatus.COMPLETED if plan_result.kind == "reply" else TaskStatus.WAITING)
                return
            else:
                tried = ", ".join(plan_result.tried or []) or "none"
                self._finish(task, handle, (
                    "I don't have a built-in way to do that, and no reasoning backend is available to plan "
                    f"it (backends tried: {tried}). I have not done anything. "
                    "Configure a Local AI (Ollama) or External API backend for open-ended requests."),
                    Outcome.UNSUPPORTED, TaskStatus.FAILED)
                return

        assert routed.plan is not None
        plan = add_implicit_dependencies(routed.plan)
        problems = self.planner.validate(plan)
        if problems:
            task.failures.extend(problems)
            self._finish(task, handle, "I could not build a valid plan: " + "; ".join(problems),
                         Outcome.FAILED, TaskStatus.FAILED)
            return
        task.plan = plan
        task.notes.extend(routed.notes)
        self._audit("plan.created", task, plan=plan.model_dump(mode="json"), created_by=plan.created_by)

        task.status = TaskStatus.RUNNING
        self._execute_plan(task, cancel)

        cancelled = any(s.status == StepStatus.CANCELLED for s in task.step_states.values())
        outcome = composer.outcome_of(task, cancelled)
        text = composer.render_task(task, outcome, routed.unhandled)
        status = {
            Outcome.VERIFIED: TaskStatus.COMPLETED,
            Outcome.EXECUTED_UNVERIFIED: TaskStatus.COMPLETED,
            Outcome.PARTIAL: TaskStatus.PARTIALLY_COMPLETED,
            Outcome.CANCELLED: TaskStatus.CANCELLED,
        }.get(outcome, TaskStatus.FAILED)
        self._finish(task, handle, text, outcome, status)

    # ------------------------------------------------------------------ plan execution
    def _parallel_safe(self, step: Step) -> bool:
        tool = self.registry.get(step.tool)
        if tool is None:
            return False
        m = tool.manifest
        return m.risk == RiskLevel.LOW and ExecMode.FOREGROUND not in m.execution_modes and not m.resources

    def _execute_plan(self, task: Task, cancel: CancelToken) -> None:
        assert task.plan is not None
        steps = task.plan.steps
        lock = threading.Lock()
        results: dict[str, ToolResult] = {}
        for s in steps:
            task.step_states[s.id] = StepState(step_id=s.id)
        started = time.monotonic()
        executed = 0

        def mark(step_id: str, status: StepStatus, note: str) -> None:
            st = task.step_states[step_id]
            st.status, st.note, st.finished_at = status, note, now()

        while True:
            pending = [s for s in steps if task.step_states[s.id].status == StepStatus.PENDING]
            if not pending:
                break
            for s in pending:
                failed_dep = next((d for d in s.depends_on if task.step_states[d].status in _FAILED_SET), None)
                if failed_dep:
                    mark(s.id, StepStatus.SKIPPED, f"dependency {failed_dep} did not succeed")
            pending = [s for s in steps if task.step_states[s.id].status == StepStatus.PENDING]
            if not pending:
                break
            if cancel.is_set():
                for s in pending:
                    mark(s.id, StepStatus.CANCELLED, "cancelled before it started")
                break
            if time.monotonic() - started > self.config.limits.task_wall_s:
                for s in pending:
                    mark(s.id, StepStatus.FAILED, "task time budget exceeded")
                task.failures.append("task time budget exceeded")
                break
            if executed >= self.config.limits.max_steps:
                for s in pending:
                    mark(s.id, StepStatus.FAILED, "step budget exceeded")
                break
            ready = [s for s in pending if all(task.step_states[d].status in _DONE_OK for d in s.depends_on)]
            if not ready:
                for s in pending:
                    mark(s.id, StepStatus.FAILED, "dependencies can never be satisfied")
                break
            parallel = [s for s in ready if self._parallel_safe(s)]
            serial = [s for s in ready if s not in parallel]
            if len(parallel) > 1:
                futs = [self._coord.submit(self._complete_step, task, s, results, lock, cancel) for s in parallel]
                for f in futs:
                    f.result()
            else:
                serial = [*parallel, *serial]
            for s in serial:
                if cancel.is_set():
                    break
                self._complete_step(task, s, results, lock, cancel)
            executed += len(ready)

    def _complete_step(self, task: Task, step: Step, results: dict[str, ToolResult],
                       lock: threading.Lock, cancel: CancelToken) -> None:
        st = task.step_states[step.id]
        current = step
        notes: list[str] = []
        st.started_at = now()
        st.status = StepStatus.RUNNING
        while True:
            with lock:
                snapshot = dict(results)
            run: StepRun = self.executor.run_step(current, task_id=task.id, results=snapshot,
                                                  cancel=cancel, mode=self.mode)
            with lock:
                st.attempts.extend(run.attempts)
                st.result, st.policy, st.status = run.result, run.policy, run.status
                results[step.id] = run.result
            if run.status in _DONE_OK:
                with lock:
                    self.ctx.register(run.entities, task.id, step.id)
                break
            if run.status == StepStatus.CANCELLED or cancel.is_set():
                break
            with lock:
                budget_left = task.recoveries < self.config.limits.max_recoveries
            rec = self.recovery.next_strategy(current, run.result, snapshot, run.resolved_arguments) if budget_left else None
            if rec is None:
                break
            with lock:
                task.recoveries += 1
            notes.append(rec.note)
            self._audit("recovery", task, step_id=step.id, note=rec.note,
                        next_arguments=rec.step.arguments)
            current = rec.step
        res = st.result
        st.finished_at = now()
        if res is not None and st.status in {StepStatus.FAILED, StepStatus.CANCELLED, StepStatus.SKIPPED}:
            st.note = res.error.message if res.error else st.note
            with lock:
                task.failures.append(f"{step.id} {step.tool}: {st.note}")
        with lock:
            task.notes.extend(notes)
            summary = (st.note if st.status in _FAILED_SET else (res.verification_note or "ok") if res else "no result")
            task.ledger.append(LedgerEntry(step_id=step.id, tool=step.tool, status=st.status,
                                           summary=str(summary)[:300], ok=bool(res and res.ok),
                                           verified=res.verified if res else None))
            if res is not None:
                self.ctx.record_result(res, str(summary)[:200])
        self.events.publish("step.finished", task_id=task.id, step_id=step.id, status=st.status.value)

    # ------------------------------------------------------------------ finishing
    def _finish(self, task: Task, handle: TaskHandle, text: str, outcome: Outcome, status: TaskStatus) -> None:
        task.final_response, task.outcome, task.status = text, outcome, status
        task.finished_at = now()
        self.ctx.add_turn("user", task.goal, task.id)
        self.ctx.add_turn("assistant", text, task.id)
        try:
            self._audit("task.finished", task, outcome=outcome.value, status=status.value,
                        response=text, failures=task.failures, notes=task.notes,
                        ledger=[e.model_dump(mode="json") for e in task.ledger],
                        duration_ms=int((task.finished_at - task.created_at) * 1000))
        except AuditError:
            log.error("audit write failed at task end")
        try:
            self.tasks.save(task)
        except Exception:
            log.exception("could not persist task %s", task.id)
        self._last_finished = task
        self.events.publish("task.finished", task_id=task.id, outcome=outcome.value)
        with self._hlock:
            self._handles.pop(task.id, None)
        handle._done.set()

    def _audit(self, kind: str, task: Task, **payload: Any) -> None:
        self.audit.append(kind, task.id, **payload)

    def _state(self) -> dict[str, Any]:
        return {
            "tools": self.registry.names(),
            "backend_lines": self.gateway.status_lines(),
            "last_task": self._last_finished,
            "active": [t for t in self.tasks.active() if t.request_class != RequestClass.CONTROL],
            "mode": self.mode.value,
        }

    def status(self) -> dict[str, Any]:
        return {"mode": self.mode.value, "backends": self.gateway.status_lines(),
                "tools": len(self.registry.names()), "active_tasks": len(self.tasks.active())}
