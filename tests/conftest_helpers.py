"""Shared fixtures for building real runtimes in isolated homes."""

from __future__ import annotations

import shutil
from pathlib import Path

from jarvis.config.schema import JarvisConfig
from jarvis.core.approvals import StaticProvider
from jarvis.core.runtime import Runtime, temp_home


def make_runtime(approve: bool = False, mode: str | None = None, extra_tools=(), extra_backends=None,
                 cfg_mut=None, cwd: Path | None = None, env: dict | None = None):
    home = temp_home()
    cfg = JarvisConfig(home_override=home)
    if mode:
        cfg.policy.mode = mode  # type: ignore[assignment]
    if cfg_mut:
        cfg_mut(cfg)
    rt = Runtime.create(cfg, use_keyring=False, approvals=StaticProvider(approve=approve),
                        extra_tools=extra_tools, extra_backends=extra_backends, cwd=cwd,
                        env=env if env is not None else None)
    return rt, home


def dispose(rt, home):
    rt.close()
    shutil.rmtree(home, ignore_errors=True)
