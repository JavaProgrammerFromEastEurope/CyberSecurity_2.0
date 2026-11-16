"""Application configuration and local paths."""
from __future__ import annotations

import os
from pathlib import Path


def data_dir() -> Path:
    """Return the local state directory, honoring CYBERSEC_HOME if set."""
    configured = os.environ.get("CYBERSEC_HOME")
    path = Path(configured).expanduser() if configured else Path.cwd() / ".cybersec"
    path.mkdir(parents=True, exist_ok=True)
    return path


def database_path() -> Path:
    return data_dir() / "cybersec.db"
