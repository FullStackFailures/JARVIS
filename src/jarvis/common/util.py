from __future__ import annotations

import datetime as _dt
import time
import uuid


def now() -> float:
    return time.time()


def utc_iso(ts: float | None = None) -> str:
    moment = _dt.datetime.fromtimestamp(ts if ts is not None else time.time(), _dt.UTC)
    return moment.strftime("%Y-%m-%dT%H:%M:%S.%fZ")


def new_id(prefix: str) -> str:
    return f"{prefix}_{uuid.uuid4().hex[:12]}"
