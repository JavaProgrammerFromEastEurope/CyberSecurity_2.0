import json
from types import SimpleNamespace

import pytest

from cybersec.scanners import NucleiAdapter, ScanContext, default_registry


def _context(url="https://example.com"):
    return ScanContext(job_id=7, target_url=url, tool="nuclei")


def test_nuclei_requires_executable():
    adapter = NucleiAdapter(executable=None)
    adapter.executable = None
    with pytest.raises(RuntimeError, match="executable not found"):
        adapter.run(_context())


def test_nuclei_uses_conservative_fixed_arguments_and_filters_scope(monkeypatch):
    in_scope = {
        "template-id": "tls-version-check",
        "matched-at": "https://example.com/login",
        "info": {"name": "Legacy TLS configuration", "severity": "medium", "description": "TLS issue"},
        "extracted-results": ["TLSv1.0"],
    }
    out_scope = {
        "template-id": "unexpected",
        "matched-at": "https://other.example/path",
        "info": {"name": "Out of scope", "severity": "critical"},
    }
    called = {}

    def fake_run(command, **kwargs):
        called["command"] = command
        called["kwargs"] = kwargs
        return SimpleNamespace(returncode=0, stdout=json.dumps(in_scope) + "\n" + json.dumps(out_scope) + "\nnot-json\n", stderr="")

    monkeypatch.setattr("cybersec.scanners.subprocess.run", fake_run)
    adapter = NucleiAdapter(executable="/usr/bin/nuclei", timeout=12)
    result = adapter.run(_context())

    command = called["command"]
    assert command[0] == "/usr/bin/nuclei"
    assert "-rate-limit" in command and command[command.index("-rate-limit") + 1] == "5"
    assert "-concurrency" in command and command[command.index("-concurrency") + 1] == "2"
    assert command[command.index("-tags") + 1] == "misconfig,exposure,ssl,tech"
    assert "-disable-update-check" in command
    assert called["kwargs"]["shell"] is False
    assert called["kwargs"]["timeout"] == 12
    assert result.status == "completed"
    assert len(result.findings) == 1
    assert result.findings[0]["severity"] == "Medium"
    assert result.findings[0]["confidence"] == "Tentative"
    assert result.raw_output["findings_discarded_out_of_scope"] == 1
    assert result.raw_output["malformed_lines"] == 1


def test_nuclei_timeout_is_reported(monkeypatch):
    def fake_run(*args, **kwargs):
        raise __import__("subprocess").TimeoutExpired(cmd=args[0], timeout=kwargs["timeout"])

    monkeypatch.setattr("cybersec.scanners.subprocess.run", fake_run)
    with pytest.raises(TimeoutError, match="job timeout"):
        NucleiAdapter(executable="nuclei", timeout=5).run(_context())


def test_nuclei_rejects_invalid_limits():
    with pytest.raises(ValueError, match="rate_limit"):
        NucleiAdapter(executable="nuclei", rate_limit=11)
    with pytest.raises(ValueError, match="concurrency"):
        NucleiAdapter(executable="nuclei", concurrency=5)
    with pytest.raises(ValueError, match="timeout"):
        NucleiAdapter(executable="nuclei", timeout=2000)


def test_default_registry_includes_nuclei():
    assert default_registry().names() == ("demo", "nuclei", "zap")
