"""Logging setup shared by the CLI and the daemon: every handler carries the secret-redacting filter."""

from __future__ import annotations

import logging
import logging.handlers
import sys

from jarvis.security.redact import REDACTOR, RedactingFilter


def setup_logging(level: str, log_dir: str | None, to_file: bool) -> None:
    root = logging.getLogger()
    root.handlers.clear()
    root.setLevel(getattr(logging, level))
    console = logging.StreamHandler(sys.stderr)
    console.setLevel(logging.WARNING)
    console.addFilter(RedactingFilter(REDACTOR))  # type: ignore[arg-type]
    root.addHandler(console)
    if to_file and log_dir:
        try:
            fh = logging.handlers.RotatingFileHandler(
                f"{log_dir}/jarvis.log", maxBytes=1_000_000, backupCount=3, encoding="utf-8")
            fh.setFormatter(logging.Formatter("%(asctime)s %(levelname)s %(name)s: %(message)s"))
            fh.addFilter(RedactingFilter(REDACTOR))  # type: ignore[arg-type]
            root.addHandler(fh)
        except OSError as exc:
            print(f"warning: file logging disabled ({exc})", file=sys.stderr)
