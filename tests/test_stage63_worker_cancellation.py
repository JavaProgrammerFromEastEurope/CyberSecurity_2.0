"""No real scanners are invoked. Only local, bounded Python fixtures execute."""
from __future__ import annotations

import os
from pathlib import Path
import signal
import subprocess
import sys
import threading
import time

import pytest

from cybersec.db import connect
from cybersec.process_supervisor import ProcessCancelled, ProcessOutcome, ProcessSupervisor
from cybersec.repository import Repository
from cybersec.scan_worker import run_scan_worker
from cybersec.scanners import AdapterRegistry, NucleiAdapter, ScanContext, ScanResult

pytestmark = pytest.mark.skipif(os.name != "posix", reason="POSIX process groups required")


def _until(predicate, timeout=4):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if predicate():
            return
        time.sleep(.02)
    raise AssertionError("timed out waiting for fixture event")


class _LocalPythonAdapter:
    """Test-only Nuclei-named fake; it runs a harmless sleeping Python fixture."""
    name = "nuclei"

    def __init__(self, pid_file):
        self.pid_file = Path(pid_file)

    def run(self, context):
        callback = context.options["_worker_interrupted"]
        command = [sys.executable, "-c",
                   "import os, pathlib, time; "
                   f"pathlib.Path({str(self.pid_file)!r}).write_text(str(os.getpid())); "
                   "time.sleep(20)"]
        ProcessSupervisor(grace_seconds=.1, poll_seconds=.03).run(
            command, timeout=5, cancelled=callback)
        return ScanResult(tool=self.name, status="completed", summary="fixture complete")


def _worker_thread(repo, pid_file, stop_event=None):
    registry = AdapterRegistry()
    registry.register(_LocalPythonAdapter(pid_file))
    outcome = {}

    def execute():
        try:
            outcome["summary"] = run_scan_worker(
                repo, worker_id="stage63-worker", lease_seconds=5,
                idle_seconds=.1, max_jobs=1, registry=registry,
                stop_event=stop_event)
        except BaseException as exc:
            outcome["error"] = exc

    thread = threading.Thread(target=execute, daemon=True)
    thread.start()
    return thread, outcome


def test_real_worker_cancel_interrupts_python_fixture(tmp_path):
    repo = Repository(tmp_path / "jobs.sqlite")
    repo.add_target("https://example.test", authorized=True)
    job = repo.create_job("https://example.test", "nuclei")
    pid_file = tmp_path / "python-fixture.pid"
    thread, outcome = _worker_thread(repo, pid_file)
    _until(pid_file.exists)
    repo.cancel_scan_job(job.id)
    thread.join(timeout=4)
    assert not thread.is_alive(), "worker did not stop cancelled process"
    assert "error" not in outcome, outcome
    assert repo.get_job(job.id).status == "cancelled"
    assert not repo.list_scan_artifacts(job.id)
    assert outcome["summary"].failed == 1  # cancelled jobs are non-completed


def test_lease_loss_aborts_process_and_blocks_reclaim(tmp_path):
    repo = Repository(tmp_path / "jobs.sqlite")
    repo.add_target("https://example.test", authorized=True)
    job = repo.create_job("https://example.test", "nuclei")
    pid_file = tmp_path / "python-fixture.pid"
    thread, outcome = _worker_thread(repo, pid_file)
    _until(pid_file.exists)
    with connect(repo.db_path) as db:
        db.execute("UPDATE scan_jobs SET lease_until='2000-01-01T00:00:00.000Z' WHERE id=?", (job.id,))
    thread.join(timeout=4)
    assert not thread.is_alive()
    assert "error" not in outcome, outcome
    assert repo.claim_next_scan_job("other-worker", lease_seconds=5) is None
    failed = repo.get_job(job.id)
    assert failed.status == "failed"
    assert "manual recovery required" in (failed.error or "")
    assert not repo.list_scan_artifacts(job.id)


def test_cooperative_sigterm_on_cancellation(tmp_path):
    marker = tmp_path / "term.txt"
    ready = tmp_path / "ready.txt"
    script = ("import signal, time, pathlib, sys; "
              f"p=pathlib.Path({str(marker)!r}); ready=pathlib.Path({str(ready)!r}); "
              "signal.signal(signal.SIGTERM, lambda *_: (p.write_text('TERM'), sys.exit(0))); "
              "ready.write_text('READY'); "
              "time.sleep(20)")
    with pytest.raises(ProcessCancelled):
        ProcessSupervisor(grace_seconds=.3, poll_seconds=.03).run(
            [sys.executable, "-u", "-c", script], timeout=5,
            cancelled=ready.exists)
    assert marker.read_text() == "TERM"


def test_sigkill_escalation_for_sigterm_ignoring_python(tmp_path):
    marker = tmp_path / "pid.txt"
    script = ("import signal, time, os, pathlib; "
              "signal.signal(signal.SIGTERM, signal.SIG_IGN); "
              f"pathlib.Path({str(marker)!r}).write_text(str(os.getpid())); "
              "time.sleep(20)")
    with pytest.raises(ProcessCancelled):
        ProcessSupervisor(grace_seconds=.12, poll_seconds=.03).run(
            [sys.executable, "-c", script], timeout=5,
            cancelled=marker.exists)
    assert marker.exists()
    pid = int(marker.read_text())
    with pytest.raises(ProcessLookupError):
        os.kill(pid, 0)


def test_external_worker_adapter_always_uses_supervisor(monkeypatch):
    from cybersec import process_supervisor
    seen = {}

    def fake_run(self, argv, *, timeout, cancelled=None, cwd=None):
        seen.update(argv=argv, timeout=timeout, cancelled=cancelled)
        return ProcessOutcome(0, "", "", .01)

    def forbid_subprocess(*args, **kwargs):
        raise AssertionError("direct subprocess bypassed supervisor")

    monkeypatch.delenv("CYBERSEC_PROCESS_SUPERVISION", raising=False)
    monkeypatch.setattr(process_supervisor.ProcessSupervisor, "run", fake_run)
    monkeypatch.setattr(subprocess, "run", forbid_subprocess)
    result = NucleiAdapter(executable="/not-installed/nuclei").run(
        ScanContext(1, "https://example.test/", "nuclei",
                    options={"_worker_interrupted": lambda: False}))
    assert result.status == "completed"
    assert callable(seen["cancelled"])


def test_cancelled_before_worker_start_is_fail_closed(tmp_path):
    repo = Repository(tmp_path / "jobs.sqlite")
    repo.add_target("https://example.test", authorized=True)
    job = repo.create_job("https://example.test", "nuclei")
    repo.claim_next_scan_job("worker", lease_seconds=5)
    repo.cancel_scan_job(job.id)
    from cybersec.runner import JobRunner
    reg = AdapterRegistry()
    reg.register(_LocalPythonAdapter(tmp_path / "should-not-exist.pid"))
    with pytest.raises(RuntimeError, match="cancelled"):
        JobRunner(repo, reg).run(job.id, worker_id="worker")
    assert not (tmp_path / "should-not-exist.pid").exists()
    assert repo.get_job(job.id).status == "cancelled"


def test_cli_worker_signal_handler_requests_stop_and_restores_previous():
    from cybersec.scan_worker import worker_signal_handlers
    stopped = threading.Event()
    previous = signal.getsignal(signal.SIGTERM)
    with worker_signal_handlers(stopped):
        signal.raise_signal(signal.SIGTERM)
        assert stopped.is_set()
    assert signal.getsignal(signal.SIGTERM) is previous


def test_service_shutdown_stops_external_fixture_requires_manual_recovery(tmp_path):
    repo = Repository(tmp_path / "jobs.sqlite")
    repo.add_target("https://example.test", authorized=True)
    job = repo.create_job("https://example.test", "nuclei")
    pid_file = tmp_path / "python-fixture.pid"
    stop = threading.Event()
    thread, outcome = _worker_thread(repo, pid_file, stop_event=stop)
    _until(pid_file.exists)
    stop.set()
    thread.join(timeout=4)
    assert not thread.is_alive()
    assert "error" not in outcome, outcome
    failed = repo.get_job(job.id)
    assert failed.status == "failed"
    assert "manual recovery required" in failed.error
    assert repo.claim_next_scan_job("other-worker", lease_seconds=5) is None
    assert not repo.list_scan_artifacts(job.id)
