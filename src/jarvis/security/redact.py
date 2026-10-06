"""Secret redaction applied to every log line and audit payload."""

from __future__ import annotations

import re
import threading
from typing import Any

REDACTED = "[REDACTED]"

_SENSITIVE_KEY = re.compile(
    r"(^|[_\-.])(api[_\-]?key|secret|token|password|passwd|authorization|credential|"
    r"private[_\-]?key|access[_\-]?key|cookie|bearer)($|[_\-.])",
    re.IGNORECASE,
)

_VALUE_PATTERNS: list[re.Pattern[str]] = [
    re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----.*?-----END [A-Z ]*PRIVATE KEY-----", re.DOTALL),
    re.compile(r"\bsk-[A-Za-z0-9_\-]{16,}"),
    re.compile(r"\bgh[pousr]_[A-Za-z0-9]{20,}"),
    re.compile(r"\bgithub_pat_[A-Za-z0-9_]{20,}"),
    re.compile(r"\bAKIA[0-9A-Z]{16}\b"),
    re.compile(r"\bxox[abprs]-[A-Za-z0-9\-]{10,}"),
    re.compile(r"\bAIza[0-9A-Za-z_\-]{30,}"),
    re.compile(r"\beyJ[A-Za-z0-9_\-]{8,}\.[A-Za-z0-9_\-]{8,}\.[A-Za-z0-9_\-]{8,}"),
    re.compile(r"(?i)\bBearer\s+[A-Za-z0-9._~+/=\-]{12,}"),
    re.compile(r"(?<=://)[^/\s:@]+:[^/\s@]+(?=@)"),
]
_ASSIGNMENT = re.compile(
    r"(?i)\b(password|passwd|pwd|secret|token|api[_\-]?key|authorization)(\s*[=:]\s*)(\"[^\"]*\"|'[^']*'|\S+)"
)


class Redactor:
    """Scrubs registered secret values, known token shapes and sensitive-keyed fields."""

    MIN_SECRET_LEN = 6

    def __init__(self) -> None:
        self._secrets: set[str] = set()
        self._lock = threading.Lock()

    def register(self, secret: str | None) -> None:
        if secret and len(secret) >= self.MIN_SECRET_LEN:
            with self._lock:
                self._secrets.add(secret)

    def clear(self) -> None:
        with self._lock:
            self._secrets.clear()

    def scrub_text(self, text: str) -> str:
        with self._lock:
            secrets = sorted(self._secrets, key=len, reverse=True)
        for s in secrets:
            if s in text:
                text = text.replace(s, REDACTED)
        for pat in _VALUE_PATTERNS:
            text = pat.sub(REDACTED, text)
        return _ASSIGNMENT.sub(lambda m: f"{m.group(1)}{m.group(2)}{REDACTED}", text)

    def scrub(self, obj: Any) -> Any:
        if isinstance(obj, str):
            return self.scrub_text(obj)
        if isinstance(obj, dict):
            out: dict[Any, Any] = {}
            for k, v in obj.items():
                if isinstance(k, str) and _SENSITIVE_KEY.search(k) and v not in (None, "", False):
                    out[k] = REDACTED
                else:
                    out[k] = self.scrub(v)
            return out
        if isinstance(obj, (list, tuple)):
            return [self.scrub(v) for v in obj]
        return obj


REDACTOR = Redactor()


class RedactingFilter:
    """logging.Filter-compatible object that scrubs record messages in place."""

    def __init__(self, redactor: Redactor | None = None) -> None:
        self.redactor = redactor or REDACTOR

    def filter(self, record: Any) -> bool:
        try:
            message = record.getMessage()
        except Exception:
            message = str(record.msg)
        record.msg = self.redactor.scrub_text(message)
        record.args = ()
        if record.exc_info:
            import traceback

            record.exc_text = self.redactor.scrub_text(
                "".join(traceback.format_exception(*record.exc_info))
            )
            record.exc_info = None
        return True
