"""Composition root: builds every subsystem and wires them together.

Everything is injectable so tests can run the *real* pipeline against temporary data
directories, a scripted approval provider, or an unreachable model endpoint.
"""

from __future__ import annotations

import logging
import os
import tempfile
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from pathlib import Path

from jarvis.brain.native_lite import NativeLiteReasoner
from jarvis.brain.recovery import RecoveryEngine
from jarvis.brain.router import Router
from jarvis.config.loader import load_config
from jarvis.config.paths import DataDirs, resolve_dirs
from jarvis.config.schema import JarvisConfig
from jarvis.core.agent import Agent
from jarvis.core.approvals import ApprovalProvider, DenyAllProvider
from jarvis.core.context import ContextManager
from jarvis.core.events import EventBus
from jarvis.core.executor import Executor
from jarvis.core.locks import ResourceLocks
from jarvis.core.planner import Planner
from jarvis.core.task_manager import TaskManager
from jarvis.models.base import Reasoner
from jarvis.models.gateway import ModelGateway
from jarvis.models.ollama import OllamaReasoner
from jarvis.models.remote import OpenAICompatReasoner
from jarvis.osal.base import OSAdapter
from jarvis.osal.detect import create_adapter
from jarvis.osal.inventory import build_inventory
from jarvis.osal.types import CapabilityInventory
from jarvis.policy.engine import PolicyEngine
from jarvis.registry.registry import ToolRegistry
from jarvis.security.audit import AuditLog
from jarvis.security.redact import REDACTOR
from jarvis.security.secrets import SecretStore
from jarvis.tools.base import Tool

log = logging.getLogger(__name__)


@dataclass
class Runtime:
    config: JarvisConfig
    dirs: DataDirs
    osal: OSAdapter
    inventory: CapabilityInventory
    registry: ToolRegistry
    policy: PolicyEngine
    executor: Executor
    audit: AuditLog
    gateway: ModelGateway
    context: ContextManager
    tasks: TaskManager
    events: EventBus
    agent: Agent
    secrets: SecretStore
    cwd: Path

    @classmethod
    def create(
        cls,
        config: JarvisConfig | None = None,
        *,
        dotenv: Mapping[str, str] | None = None,
        env: Mapping[str, str] | None = None,
        osal: OSAdapter | None = None,
        approvals: ApprovalProvider | None = None,
        extra_tools: Sequence[Tool | type[Tool]] = (),
        extra_backends: Mapping[str, Reasoner] | None = None,
        cwd: Path | None = None,
        use_keyring: bool = True,
    ) -> Runtime:
        if config is None:
            config, loaded_dotenv = load_config(env=env)
            dotenv = dotenv if dotenv is not None else loaded_dotenv
        dirs = resolve_dirs(config.home_override)
        dirs.ensure()
        cwd = (cwd or Path.cwd()).resolve()

        secrets = SecretStore(env=env if env is not None else os.environ, dotenv=dotenv,
                              use_keyring=use_keyring)
        adapter = osal or create_adapter(env=env)
        inventory = build_inventory(adapter)

        registry = ToolRegistry()
        registry.load_builtin()
        for t in extra_tools:
            registry.register(t)

        backends: dict[str, Reasoner] = {
            "native": NativeLiteReasoner(),
            "ollama": OllamaReasoner(config.models.ollama),
            "remote": OpenAICompatReasoner(
                config.models.remote, api_key=lambda: secrets.get(config.models.remote.api_key_name)),
        }
        backends.update(extra_backends or {})
        fallback: list[str] = [b for b in config.models.fallback_order if b != config.models.default_backend]
        if "native" not in fallback and config.models.default_backend != "native":
            fallback.append("native")
        gateway = ModelGateway(
            backends, default=config.models.default_backend, fallback_order=fallback,
            health_ttl_s=config.models.health_ttl_s, max_retries=config.models.max_retries,
            retry_backoff_s=config.models.retry_backoff_s,
        )

        audit = AuditLog(dirs.db / "audit.db", REDACTOR)
        policy = PolicyEngine(config.policy, adapter, cwd)
        events = EventBus()
        executor = Executor(
            registry=registry, policy=policy, osal=adapter, inventory=inventory, config=config,
            audit=audit, approvals=approvals or DenyAllProvider(), locks=ResourceLocks(),
            events=events, cwd=cwd,
            notes_dir=Path(config.storage.notes_dir).expanduser() if config.storage.notes_dir else dirs.notes,
        )
        context = ContextManager(inventory, cwd, config.policy.mode)
        tasks = TaskManager(dirs.db / "tasks.db", REDACTOR)
        planner = Planner(registry, gateway, config, adapter.name, inventory)
        agent = Agent(
            config=config, osal=adapter, inventory=inventory, registry=registry, executor=executor,
            router=Router(), planner=planner, recovery=RecoveryEngine(), context=context,
            gateway=gateway, audit=audit, tasks=tasks, events=events, mode=config.policy.mode,
        )
        audit.append("runtime.started", None, platform=adapter.name, mode=config.policy.mode.value,
                     default_backend=config.models.default_backend, tools=registry.names())
        return cls(config, dirs, adapter, inventory, registry, policy, executor, audit, gateway,
                   context, tasks, events, agent, secrets, cwd)

    def close(self) -> None:
        self.agent.shutdown()
        self.executor.shutdown()
        self.tasks.close()
        self.audit.close()


def temp_home() -> str:
    """A fresh isolated JARVIS_HOME (used by self-test and tests)."""
    return tempfile.mkdtemp(prefix="jarvis-home-")
