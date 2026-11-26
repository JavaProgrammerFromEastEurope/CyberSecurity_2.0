"""Day01 fail-closed guard tests; actual end-to-end path runs in CI."""
from __future__ import annotations
from unittest.mock import patch
import importlib.util
from pathlib import Path
import pytest

SPEC = importlib.util.spec_from_file_location("day01_smoke", Path(__file__).resolve().parents[1] / "tools" / "day01_smoke.py")
assert SPEC is not None and SPEC.loader is not None
module = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(module)


@pytest.mark.parametrize("key,value", [
    ("CYBERSEC_EXECUTION_MODE","production"),
    ("CYBERSEC_RUNTIME_MODE","PRODUCTION"),
    ("CYBERSEC_EXECUTION_MODE","prod"),
])
def test_production_never_smoked(monkeypatch, key, value):
    monkeypatch.setenv(key, value)
    with pytest.raises(RuntimeError, match="FAIL_CLOSED_PRODUCTION_MODE"):
        module.guard_environment()


def test_root_denied_by_default(monkeypatch):
    monkeypatch.delenv("CYBERSEC_DAY01_ALLOW_ROOT_CI", raising=False)
    monkeypatch.delenv("CYBERSEC_EXECUTION_MODE", raising=False)
    monkeypatch.delenv("CYBERSEC_RUNTIME_MODE", raising=False)
    with patch.object(module.os, "geteuid", return_value=0):
        with pytest.raises(RuntimeError, match="REFUSE_ROOT_EXECUTION"):
            module.guard_environment()


def test_unprivileged_demo_permitted(monkeypatch):
    monkeypatch.delenv("CYBERSEC_EXECUTION_MODE", raising=False)
    monkeypatch.delenv("CYBERSEC_RUNTIME_MODE", raising=False)
    with patch.object(module.os, "geteuid", return_value=10001):
        assert module.guard_environment() is None


def test_demo_url_is_loopback():
    assert module.TARGET.startswith("http://127.0.0.1:")
    assert module.TARGET.endswith("/")


def test_network_proxy_disabled_by_default():
    import inspect
    assert "ProxyHandler({})" in inspect.getsource(module.http_get)
