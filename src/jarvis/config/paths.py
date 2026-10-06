"""Platform-aware data directories (platformdirs); never hard-coded OS paths."""

from __future__ import annotations

import os
from dataclasses import dataclass
from pathlib import Path

import platformdirs

from jarvis.osal.host import IS_POSIX

APP = "JARVIS"


@dataclass(frozen=True)
class DataDirs:
    config: Path
    data: Path
    db: Path
    logs: Path
    cache: Path
    artifacts: Path
    screens: Path
    index: Path
    run: Path
    notes: Path  # created lazily by the notes tool, not by ensure()

    def all(self) -> list[Path]:
        return [self.config, self.data, self.db, self.logs, self.cache, self.artifacts,
                self.screens, self.index, self.run]

    def ensure(self) -> None:
        for d in self.all():
            d.mkdir(parents=True, exist_ok=True)
            if IS_POSIX:
                os.chmod(d, 0o700)


def resolve_dirs(home_override: str | None = None) -> DataDirs:
    if home_override:
        base = Path(home_override).expanduser().resolve()
        return DataDirs(
            config=base / "config",
            data=base / "data",
            db=base / "data" / "db",
            logs=base / "logs",
            cache=base / "cache",
            artifacts=base / "data" / "artifacts",
            screens=base / "data" / "artifacts" / "screens",
            index=base / "data" / "index",
            run=base / "run",
            notes=base / "notes",
        )
    data = Path(platformdirs.user_data_dir(APP, appauthor=False))
    return DataDirs(
        config=Path(platformdirs.user_config_dir(APP, appauthor=False)),
        data=data,
        db=data / "db",
        logs=Path(platformdirs.user_log_dir(APP, appauthor=False)),
        cache=Path(platformdirs.user_cache_dir(APP, appauthor=False)),
        artifacts=data / "artifacts",
        screens=data / "artifacts" / "screens",
        index=data / "index",
        run=Path(platformdirs.user_runtime_dir(APP, appauthor=False)),
        notes=Path(platformdirs.user_documents_dir()) / APP / "notes",
    )
