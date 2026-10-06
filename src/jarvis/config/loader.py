"""Configuration loading: defaults < config.toml < .env < process environment."""

from __future__ import annotations

import json
import os
import tomllib
from collections.abc import Mapping
from pathlib import Path
from typing import Any

from pydantic import ValidationError

from jarvis.config.paths import resolve_dirs
from jarvis.config.schema import JarvisConfig

ENV_PREFIX = "JARVIS_"


class ConfigError(Exception):
    pass


def read_dotenv(path: Path) -> dict[str, str]:
    """Minimal .env parser (KEY=VALUE, '#' comments, optional quotes). Does not touch os.environ."""
    out: dict[str, str] = {}
    try:
        text = path.read_text(encoding="utf-8")
    except FileNotFoundError:
        return out
    except OSError as exc:
        raise ConfigError(f"cannot read {path}: {exc}") from exc
    for lineno, raw in enumerate(text.splitlines(), 1):
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        if line.startswith("export "):
            line = line[7:].lstrip()
        if "=" not in line:
            raise ConfigError(f"{path}:{lineno}: expected KEY=VALUE")
        key, _, value = line.partition("=")
        value = value.strip()
        if len(value) >= 2 and value[0] == value[-1] and value[0] in "\"'":
            value = value[1:-1]
        out[key.strip()] = value
    return out


def _coerce(value: str) -> Any:
    low = value.strip().lower()
    if low in {"true", "false"}:
        return low == "true"
    try:
        return json.loads(value)
    except json.JSONDecodeError:
        return value


def _set_nested(target: dict[str, Any], dotted: list[str], value: Any) -> None:
    cur = target
    for part in dotted[:-1]:
        nxt = cur.get(part)
        if not isinstance(nxt, dict):
            nxt = {}
            cur[part] = nxt
        cur = nxt
    cur[dotted[-1]] = value


# Secrets and non-config variables that share the JARVIS_ prefix.
_NON_CONFIG_SUFFIXES = ("API_KEY", "_TOKEN", "_SECRET", "_PASSWORD")


def _env_overrides(env: Mapping[str, str]) -> dict[str, Any]:
    out: dict[str, Any] = {}
    for key, value in env.items():
        if not key.startswith(ENV_PREFIX) or "__" not in key:
            continue  # only JARVIS_SECTION__KEY form is a config override
        if key.endswith(_NON_CONFIG_SUFFIXES):
            continue
        path = [p.lower() for p in key[len(ENV_PREFIX):].split("__")]
        _set_nested(out, path, _coerce(value))
    return out


def _merge(base: dict[str, Any], extra: dict[str, Any]) -> dict[str, Any]:
    for k, v in extra.items():
        if isinstance(v, dict) and isinstance(base.get(k), dict):
            _merge(base[k], v)
        else:
            base[k] = v
    return base


def load_config(
    *,
    env: Mapping[str, str] | None = None,
    config_file: Path | None = None,
    dotenv_file: Path | None = None,
    cwd: Path | None = None,
) -> tuple[JarvisConfig, dict[str, str]]:
    """Return (config, dotenv_values). dotenv values are returned for the SecretStore only."""
    env = env if env is not None else os.environ
    cwd = cwd or Path.cwd()

    home_override = env.get("JARVIS_HOME")
    dirs = resolve_dirs(home_override)

    raw: dict[str, Any] = {}
    cfg_path = config_file or dirs.config / "config.toml"
    if cfg_path.is_file():
        try:
            raw = tomllib.loads(cfg_path.read_text(encoding="utf-8"))
        except (OSError, tomllib.TOMLDecodeError) as exc:
            raise ConfigError(f"invalid config file {cfg_path}: {exc}") from exc

    dotenv = read_dotenv(dotenv_file or cwd / ".env")
    _merge(raw, _env_overrides(dotenv))
    _merge(raw, _env_overrides(env))
    if home_override:
        raw["home_override"] = home_override

    try:
        return JarvisConfig.model_validate(raw), dotenv
    except ValidationError as exc:
        problems = "; ".join(
            f"{'.'.join(str(p) for p in e['loc'])}: {e['msg']}" for e in exc.errors()
        )
        raise ConfigError(f"invalid configuration: {problems}") from exc
