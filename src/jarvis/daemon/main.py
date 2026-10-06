"""``jarvisd`` entry point (foreground). Stop with Ctrl-C, SIGTERM, or ``jarvis daemon stop``."""

from __future__ import annotations

import argparse
import os
import signal
import sys
from collections.abc import Sequence

from jarvis import __version__
from jarvis.config import ConfigError, load_config
from jarvis.config.paths import resolve_dirs
from jarvis.core.models import PermissionMode
from jarvis.daemon.server import AlreadyRunning, Daemon
from jarvis.security.logsetup import setup_logging


def main(argv: Sequence[str] | None = None) -> int:
    p = argparse.ArgumentParser(prog="jarvisd", description="JARVIS daemon (foreground)")
    p.add_argument("--home", help="use this directory for ALL config/data/logs/run files")
    p.add_argument("--mode", choices=[m.value.lower() for m in PermissionMode])
    p.add_argument("--version", action="store_true")
    args = p.parse_args(argv)
    if args.version:
        print(f"jarvisd {__version__}")
        return 0
    env = {**os.environ, "JARVIS_HOME": args.home} if args.home else None
    try:
        config, dotenv = load_config(env=env)
    except ConfigError as exc:
        print(f"configuration error: {exc}", file=sys.stderr)
        return 2
    if args.mode:
        config = config.model_copy(update={"policy": config.policy.model_copy(
            update={"mode": PermissionMode(args.mode.upper())})})
    dirs = resolve_dirs(config.home_override)
    dirs.ensure()
    setup_logging(config.logging.level, str(dirs.logs), config.logging.log_to_file)
    daemon = Daemon.create(config, dotenv=dotenv, env=env)

    def on_signal(signum: int, _frame: object) -> None:
        daemon.stop()

    signal.signal(signal.SIGINT, on_signal)
    if hasattr(signal, "SIGTERM"):
        signal.signal(signal.SIGTERM, on_signal)
    print(f"jarvisd {__version__} listening on {daemon.endpoint.address} "
          f"(mode {config.policy.mode.value}); Ctrl-C to stop", flush=True)
    try:
        daemon.serve_forever()
    except AlreadyRunning as exc:
        print(str(exc), file=sys.stderr)
        daemon.rt.close()
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
