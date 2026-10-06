"""Deterministic policy engine. No LLM, no network, no randomness.

Decision = f(tool manifest, arguments, permission mode, taint, platform state, scope config).
The agent can never bypass it: the executor calls ``evaluate`` for every step and refuses to
run a step without a PolicyDecision.
"""

from __future__ import annotations

from collections.abc import Callable, Mapping
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from jarvis.config.schema import PolicyConfig
from jarvis.core.models import Decision, PermissionMode, PolicyDecision, RiskLevel, ToolManifest
from jarvis.osal.base import OSAdapter
from jarvis.policy import commands as cmd
from jarvis.policy.scopes import ScopeChecker
from jarvis.security.broker import PrivilegeBroker, UnavailableBroker

MODE_GRANTS: dict[PermissionMode, frozenset[str]] = {
    PermissionMode.RESTRICTED: frozenset(
        {"system.read", "fs.read", "net.read", "apps.read", "proc.read", "notes.write"}
    ),
    PermissionMode.NORMAL: frozenset(
        {"system.read", "fs.read", "net.read", "apps.read", "proc.read", "apps.launch",
         "proc.exec_readonly", "proc.exec", "fs.write", "notes.write"}
    ),
    PermissionMode.FULL_ACCESS: frozenset(
        {"system.read", "fs.read", "net.read", "apps.read", "proc.read", "apps.launch",
         "proc.exec_readonly", "proc.exec", "fs.write", "notes.write", "priv.elevate"}
    ),
}


@dataclass
class PolicyRequest:
    manifest: ToolManifest
    arguments: Mapping[str, Any]
    mode: PermissionMode
    tainted: bool = False
    cwd: Path = field(default_factory=Path.cwd)


@dataclass
class Assessment:
    risk: RiskLevel
    reasons: list[str] = field(default_factory=list)
    permissions: list[str] | None = None  # None => manifest.permissions
    force: Decision | None = None


Assessor = Callable[["PolicyEngine", PolicyRequest], Assessment]


class PolicyEngine:
    def __init__(
        self,
        config: PolicyConfig,
        adapter: OSAdapter,
        cwd: Path | None = None,
        broker: PrivilegeBroker | None = None,
    ) -> None:
        self.config = config
        self.adapter = adapter
        self.cwd = cwd or Path.cwd()
        self.broker = broker or UnavailableBroker()
        self.scopes = ScopeChecker(config.fs_read_roots, self.cwd)
        self._assessors: dict[str, Assessor] = {
            "terminal.execute": _assess_terminal,
            "fs.list": _assess_path_arg,
            "fs.read": _assess_path_arg,
            "fs.search": _assess_path_arg,
            "system.disk": _assess_path_arg,
        }

    def register_assessor(self, tool_name: str, fn: Assessor) -> None:
        self._assessors[tool_name] = fn

    # ------------------------------------------------------------------ evaluation
    def evaluate(self, req: PolicyRequest) -> PolicyDecision:
        m = req.manifest
        assess = self._assessors.get(m.name)
        a = assess(self, req) if assess else Assessment(risk=m.risk)
        reasons = list(a.reasons)
        required = a.permissions if a.permissions is not None else m.permissions

        def out(decision: Decision, extra: str | None = None) -> PolicyDecision:
            if extra:
                reasons.append(extra)
            return PolicyDecision(
                decision=decision,
                risk=a.risk,
                reasons=reasons,
                approval_type="once" if decision == Decision.ASK else "none",
                mode=req.mode,
                tainted=req.tainted,
            )

        if a.force == Decision.DENY:
            return out(Decision.DENY)

        if "priv.elevate" in required and not self.broker.status().available:
            return out(Decision.DENY, f"privileged execution unavailable: {self.broker.status().reason}")

        missing = sorted(set(required) - MODE_GRANTS[req.mode])
        if missing:
            return out(Decision.DENY, f"permission mode {req.mode.value} does not grant: {', '.join(missing)}")

        decision = self._by_risk(a.risk, req, m.name)
        if a.force == Decision.ASK and decision == Decision.ALLOW:
            decision = Decision.ASK
            reasons.append("tool-specific assessment requires approval")
        if req.tainted and a.risk != RiskLevel.LOW:
            reasons.append("arguments derive from untrusted content")
        return out(decision)

    def _by_risk(self, risk: RiskLevel, req: PolicyRequest, tool: str) -> Decision:
        if risk == RiskLevel.LOW:
            return Decision.ALLOW
        if risk == RiskLevel.MEDIUM:
            if req.mode == PermissionMode.RESTRICTED:
                return Decision.DENY
            if tool in self.config.auto_allow_medium and not req.tainted:
                return Decision.ALLOW
            return Decision.ASK
        # HIGH
        if req.mode != PermissionMode.FULL_ACCESS:
            return Decision.DENY
        return Decision.DENY if req.tainted else Decision.ASK


# ---------------------------------------------------------------------------- assessors
def _assess_path_arg(engine: PolicyEngine, req: PolicyRequest) -> Assessment:
    raw = str(req.arguments.get("path", req.arguments.get("root", ".")))
    pc = engine.scopes.classify(raw, req.cwd)
    if pc.sensitive:
        return Assessment(RiskLevel.HIGH, [pc.reason or "sensitive path"], force=Decision.DENY)
    if not pc.in_scope:
        return Assessment(RiskLevel.MEDIUM, [pc.reason or "outside read scope"])
    return Assessment(RiskLevel.LOW, ["path is inside the configured read scope"])


def _assess_terminal(engine: PolicyEngine, req: PolicyRequest) -> Assessment:
    argv = req.arguments.get("argv")
    if (
        not isinstance(argv, list)
        or not argv
        or not all(isinstance(x, str) for x in argv)
        or any(("\x00" in x or "\n" in x or "\r" in x) for x in argv)
    ):
        return Assessment(RiskLevel.HIGH, ["malformed argv"], force=Decision.DENY)

    reasons: list[str] = []
    risk = RiskLevel.LOW
    cwd_arg = req.arguments.get("cwd")
    if cwd_arg is not None:
        pc = engine.scopes.classify(str(cwd_arg), req.cwd)
        if pc.sensitive:
            return Assessment(RiskLevel.HIGH, [pc.reason or "sensitive cwd"], force=Decision.DENY)
        if not pc.in_scope:
            risk = RiskLevel.MEDIUM
            reasons.append("working directory is outside the read scope")

    recipes = engine.adapter.command_recipes().values()
    if any(argv == r for alts in recipes for r in alts):
        return Assessment(risk, [*reasons, "exact built-in read-only recipe"], ["proc.exec_readonly"])

    name = argv[0]
    cat = cmd.category(name)
    stem = cmd.command_stem(name)
    if cat == "interpreter":
        return Assessment(
            RiskLevel.HIGH,
            [f"{stem!r} is a shell/interpreter that can run arbitrary code; shell mode is not available in Milestone 1"],
            force=Decision.DENY,
        )
    if cat == "destructive":
        return Assessment(
            RiskLevel.HIGH,
            [f"{stem!r} is destructive, privilege-changing or system-modifying; refused in Milestone 1"],
            force=Decision.DENY,
        )
    if cat == "network":
        return Assessment(
            RiskLevel.HIGH, [f"{stem!r} performs network egress"], ["proc.exec"]
        )

    system_path = engine.adapter.resolve_system_executable(name)
    if system_path is not None:
        if stem in cmd.READONLY_COMMANDS and cmd.READONLY_COMMANDS[stem](argv[1:]):
            return Assessment(risk, [*reasons, f"{stem!r} with these arguments is on the read-only allow-list"],
                              ["proc.exec_readonly"])
        if stem in cmd.PATH_TAKING_READONLY:
            ok, paths = cmd.ls_flags_ok(argv[1:])
            if ok:
                worst = risk
                for p in paths or ["."]:
                    pc = engine.scopes.classify(p, Path(str(cwd_arg)) if cwd_arg else req.cwd)
                    if pc.sensitive:
                        return Assessment(RiskLevel.HIGH, [pc.reason or "sensitive path"], force=Decision.DENY)
                    if not pc.in_scope:
                        worst = RiskLevel.MEDIUM
                        reasons.append(f"{p!r} is outside the read scope")
                return Assessment(worst, [*reasons, f"{stem!r} listing is read-only"], ["proc.exec_readonly"])
    return Assessment(
        RiskLevel.MEDIUM,
        [*reasons, f"{stem!r} with these arguments is not on the read-only allow-list; approval required"],
        ["proc.exec"],
    )
