"""Build the explicit capability inventory for the current platform."""

from __future__ import annotations

import time

from jarvis.osal.base import OSAdapter
from jarvis.osal.types import (
    Availability,
    CapabilityEntry,
    CapabilityInventory,
)


def build_inventory(adapter: OSAdapter, *, discover_apps: bool = True) -> CapabilityInventory:
    caps = adapter.probe_capabilities()
    apps_found = 0
    browsers: list[str] = []
    if discover_apps:
        try:
            apps, _diag = adapter.discover_applications()
            apps_found = len(apps)
            browsers = [a.name for a in apps if a.kind == "browser"]
            if not apps:
                caps["apps.discover"] = CapabilityEntry(
                    status=Availability.DEGRADED,
                    implemented=True,
                    reason="discovery ran but found no applications",
                )
        except Exception as exc:  # discovery must never break startup
            caps["apps.discover"] = CapabilityEntry(
                status=Availability.UNAVAILABLE,
                implemented=True,
                reason=f"discovery failed: {type(exc).__name__}: {exc}",
            )
    return CapabilityInventory(
        os=adapter.detect_os(),
        shell=adapter.detect_shell(),
        session=adapter.detect_session(),
        privilege=adapter.privilege_state(),
        capabilities=caps,
        apps_found=apps_found,
        browsers_found=browsers,
        generated_at=time.time(),
    )
