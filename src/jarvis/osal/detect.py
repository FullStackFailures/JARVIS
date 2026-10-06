"""Platform selection. This is the only place (with osal/*) allowed to look at sys.platform."""

from __future__ import annotations

import sys
from collections.abc import Mapping

from jarvis.osal.base import OSAdapter


def detect_platform_name(platform_override: str | None = None) -> str:
    if platform_override:
        return platform_override
    if sys.platform.startswith("win"):
        return "windows"
    if sys.platform.startswith("linux"):
        return "linux"
    raise RuntimeError(
        f"unsupported platform {sys.platform!r}: JARVIS supports Windows and Linux only"
    )


def create_adapter(
    platform_override: str | None = None, env: Mapping[str, str] | None = None
) -> OSAdapter:
    name = detect_platform_name(platform_override)
    if name == "linux":
        from jarvis.osal.linux import LinuxAdapter

        return LinuxAdapter(env)
    if name == "windows":
        from jarvis.osal.windows import WindowsAdapter

        return WindowsAdapter(env)
    raise RuntimeError(f"no adapter for platform {name!r}")
