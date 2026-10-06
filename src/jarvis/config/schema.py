"""Typed configuration schema. Secrets are NEVER fields here (see security.secrets)."""

from __future__ import annotations

from typing import Literal

from pydantic import BaseModel, ConfigDict, Field

from jarvis.core.models import PermissionMode


class _C(BaseModel):
    model_config = ConfigDict(extra="forbid")


class OllamaConfig(_C):
    enabled: bool = False
    base_url: str = "http://127.0.0.1:11434"
    model: str | None = None
    timeout_s: float = 60.0
    health_timeout_s: float = 3.0


class RemoteConfig(_C):
    enabled: bool = False
    provider: Literal["openai_compat"] = "openai_compat"
    base_url: str = "https://api.openai.com/v1"
    model: str | None = None
    api_key_name: str = "JARVIS_REMOTE_API_KEY"  # NAME of the secret, never its value
    timeout_s: float = 60.0
    health_timeout_s: float = 5.0
    allow_task_content: bool = False  # must be true before task text may be sent off-machine


BackendName = Literal["native", "ollama", "remote"]


def _default_fallback_order() -> list[BackendName]:
    # A typed factory: a bare ``lambda: ["native"]`` is inferred as list[str], which a type checker rejects for
    # list[Literal[...]] (reported by mypy on Windows).
    return ["native"]


class ModelsConfig(_C):
    default_backend: BackendName = "native"
    fallback_order: list[BackendName] = Field(default_factory=_default_fallback_order)
    health_ttl_s: float = 60.0
    max_retries: int = Field(default=2, ge=0, le=5)
    retry_backoff_s: float = Field(default=0.5, ge=0)
    ollama: OllamaConfig = Field(default_factory=OllamaConfig)
    remote: RemoteConfig = Field(default_factory=RemoteConfig)


class PolicyConfig(_C):
    mode: PermissionMode = PermissionMode.NORMAL
    fs_read_roots: list[str] = Field(default_factory=list)  # empty => home, cwd, temp dir
    auto_allow_medium: list[str] = Field(default_factory=lambda: ["apps.open"])


class AppsConfig(_C):
    require_graphical_session: bool = True
    verify_timeout_s: float = Field(default=3.0, gt=0)


class LimitsConfig(_C):
    max_parallel: int = Field(default=4, ge=1, le=32)
    max_steps: int = Field(default=20, ge=1)
    max_recoveries: int = Field(default=3, ge=0)
    task_wall_s: float = Field(default=120.0, gt=0)
    executor_grace_s: float = Field(default=1.5, gt=0)
    lock_timeout_s: float = Field(default=10.0, gt=0)
    mechanical_retries: int = Field(default=1, ge=0, le=3)


class LoggingConfig(_C):
    level: Literal["DEBUG", "INFO", "WARNING", "ERROR"] = "INFO"
    log_to_file: bool = True


class StorageConfig(_C):
    notes_dir: str | None = None  # default: <Documents>/JARVIS/notes (or <home_override>/notes)


class IpcConfig(_C):
    handshake_timeout_s: float = Field(default=5.0, gt=0, le=60)   # whole mutual handshake, per connection
    max_pending_handshakes: int = Field(default=16, ge=1, le=256)  # connections still authenticating; extras dropped
    require_peer_identity: bool = True  # fail closed when the OS cannot tell who is on the other end


class JarvisConfig(_C):
    home_override: str | None = None  # relocates ALL data dirs (tests, portable installs)
    models: ModelsConfig = Field(default_factory=ModelsConfig)
    policy: PolicyConfig = Field(default_factory=PolicyConfig)
    apps: AppsConfig = Field(default_factory=AppsConfig)
    limits: LimitsConfig = Field(default_factory=LimitsConfig)
    logging: LoggingConfig = Field(default_factory=LoggingConfig)
    storage: StorageConfig = Field(default_factory=StorageConfig)
    ipc: IpcConfig = Field(default_factory=IpcConfig)
