"""Safe, size-bounded logging configuration for CLI worker operations."""
from __future__ import annotations

import logging
import os
from logging.handlers import RotatingFileHandler
from pathlib import Path


def configure_logging() -> None:
    """Configure JSON worker logs and optional rotating file output.

    CYBERSEC_LOG_FILE enables local file logging. Size and backup count are bounded
    and parsed conservatively; payloads must never be passed to worker log calls.
    """
    logger = logging.getLogger("cybersec")
    if getattr(logger, "_cybersec_configured", False):
        return
    logger.setLevel(logging.INFO)
    logger.propagate = False
    formatter = logging.Formatter("%(message)s")
    stream = logging.StreamHandler()
    stream.setFormatter(formatter)
    logger.addHandler(stream)

    filename = os.environ.get("CYBERSEC_LOG_FILE", "").strip()
    if filename:
        path = Path(filename).expanduser()
        path.parent.mkdir(parents=True, exist_ok=True)
        try:
            max_bytes = int(os.environ.get("CYBERSEC_LOG_MAX_BYTES", str(5 * 1024 * 1024)))
            backups = int(os.environ.get("CYBERSEC_LOG_BACKUPS", "3"))
        except ValueError as exc:
            raise ValueError("CYBERSEC_LOG_MAX_BYTES and CYBERSEC_LOG_BACKUPS must be integers") from exc
        if not 1024 <= max_bytes <= 100 * 1024 * 1024:
            raise ValueError("CYBERSEC_LOG_MAX_BYTES must be between 1024 and 104857600")
        if not 1 <= backups <= 20:
            raise ValueError("CYBERSEC_LOG_BACKUPS must be between 1 and 20")
        file_handler = RotatingFileHandler(path, maxBytes=max_bytes, backupCount=backups, encoding="utf-8")
        file_handler.setFormatter(formatter)
        logger.addHandler(file_handler)
    setattr(logger, "_cybersec_configured", True)
