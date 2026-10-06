"""Secret lookup: process env, .env values, then the OS keyring (if installed). Never logged."""

from __future__ import annotations

import os
from collections.abc import Mapping

from jarvis.security.redact import REDACTOR, Redactor


class SecretStore:
    def __init__(
        self,
        env: Mapping[str, str] | None = None,
        dotenv: Mapping[str, str] | None = None,
        redactor: Redactor | None = None,
        use_keyring: bool = True,
    ) -> None:
        self._env = env if env is not None else os.environ
        self._dotenv = dict(dotenv or {})
        self._redactor = redactor or REDACTOR
        self._use_keyring = use_keyring

    def get(self, name: str) -> str | None:
        value = self._env.get(name) or self._dotenv.get(name)
        if not value and self._use_keyring:
            value = self._from_keyring(name)
        if value:
            self._redactor.register(value)
        return value or None

    def has(self, name: str) -> bool:
        # Look-up registers the value with the redactor as a side effect; that is intended.
        return self.get(name) is not None

    @staticmethod
    def _from_keyring(name: str) -> str | None:
        try:
            import keyring  # optional dependency
        except ImportError:
            return None
        try:
            return keyring.get_password("jarvis", name)
        except Exception:  # keyring backends fail in many ways on headless systems
            return None

    def __repr__(self) -> str:  # never expose contents
        return "SecretStore(<redacted>)"
