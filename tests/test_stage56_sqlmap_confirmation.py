import subprocess
from unittest.mock import patch
import pytest
from cybersec.scanners import ScanContext, SqlmapConfirmationAdapter, default_registry


def ctx(**updates):
    opts = dict(authorized=True, candidate_recorded=True,
                candidate_url="https://example.test/app?id=1", parameter="id")
    opts.update(updates)
    return ScanContext(1, "https://example.test/app", "sqlmap", opts)


def test_no_implicit_sqlmap_execution():
    with pytest.raises(LookupError):
        default_registry().get("sqlmap")


@pytest.mark.parametrize("updates", [
    {"authorized": False}, {"candidate_recorded": False},
    {"candidate_url": "https://evil.test/app?id=1"},
    {"candidate_url": "https://example.test/other?id=1"},
    {"candidate_url": "https://example.test/app?other=1"},
    {"parameter": "id;--dump"},
])
def test_reject_invalid_or_unauthorized(updates):
    with patch("cybersec.scanners.subprocess.run") as run:
        with pytest.raises((ValueError, PermissionError)):
            SqlmapConfirmationAdapter("sqlmap").run(ctx(**updates))
        run.assert_not_called()


def test_confirmed_and_safe_argv():
    output = "Parameter: id (GET)\n    Type: boolean-based blind\n"
    with patch("cybersec.scanners.subprocess.run", return_value=subprocess.CompletedProcess([], 0, output, "")) as run:
        result = SqlmapConfirmationAdapter("sqlmap").run(ctx())
    assert len(result.findings) == 1
    argv = run.call_args.args[0]
    assert "--risk=1" in argv and "--threads=1" in argv
    assert not any(x in argv for x in ("--dump", "--dbs", "--os-shell", "--all"))
    assert run.call_args.kwargs["shell"] is False


def test_inconclusive_does_not_create_finding():
    with patch("cybersec.scanners.subprocess.run", return_value=subprocess.CompletedProcess([], 0, "no injection", "")):
        result = SqlmapConfirmationAdapter("sqlmap").run(ctx())
    assert not result.findings


def test_timeout():
    with patch("cybersec.scanners.subprocess.run", side_effect=subprocess.TimeoutExpired("sqlmap", 5)):
        with pytest.raises(TimeoutError):
            SqlmapConfirmationAdapter("sqlmap").run(ctx())


def test_nonzero_exit():
    with patch("cybersec.scanners.subprocess.run", return_value=subprocess.CompletedProcess([], 2, "", "error")):
        with pytest.raises(RuntimeError):
            SqlmapConfirmationAdapter("sqlmap").run(ctx())
