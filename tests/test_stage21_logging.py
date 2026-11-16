import json
import logging

import pytest

from cybersec.logging_setup import configure_logging


def reset_logger():
    logger = logging.getLogger("cybersec")
    for handler in list(logger.handlers):
        handler.close()
        logger.removeHandler(handler)
    if hasattr(logger, "_cybersec_configured"):
        delattr(logger, "_cybersec_configured")


def test_configure_logging_writes_structured_record_to_rotating_file(tmp_path, monkeypatch):
    reset_logger()
    path = tmp_path / "logs" / "worker.jsonl"
    monkeypatch.setenv("CYBERSEC_LOG_FILE", str(path))
    monkeypatch.setenv("CYBERSEC_LOG_MAX_BYTES", "1024")
    monkeypatch.setenv("CYBERSEC_LOG_BACKUPS", "2")
    configure_logging()
    try:
        logging.getLogger("cybersec.worker").info(json.dumps({"event": "test_record", "count": 1}))
        for handler in logging.getLogger("cybersec").handlers:
            handler.flush()
        records = path.read_text(encoding="utf-8").splitlines()
        assert json.loads(records[-1]) == {"event": "test_record", "count": 1}
    finally:
        reset_logger()


def test_logging_rejects_unbounded_rotation_settings(monkeypatch):
    reset_logger()
    monkeypatch.setenv("CYBERSEC_LOG_FILE", "/tmp/cybersec-test-worker.jsonl")
    monkeypatch.setenv("CYBERSEC_LOG_MAX_BYTES", "1")
    try:
        with pytest.raises(ValueError, match="between 1024"):
            configure_logging()
    finally:
        reset_logger()
        import os
        try:
            os.unlink("/tmp/cybersec-test-worker.jsonl")
        except FileNotFoundError:
            pass
