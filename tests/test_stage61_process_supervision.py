"""Stage 61: offline real-process and SQLite worker supervision tests.

All test executables are local Python fixtures, not real scanning tools.
"""
from __future__ import annotations

import os
import pathlib
import signal
import subprocess
import sys
import threading
import time
from concurrent.futures import ThreadPoolExecutor

import pytest

from cybersec.process_supervision import (
    ScanCancelled, ScanExecutionUncertain, run_supervised,
)
from cybersec.repository import Repository
from cybersec.scan_worker import run_scan_worker
from cybersec.scanners import AdapterRegistry, NucleiAdapter, ScanContext, ZapPassiveAdapter


def _until(condition, timeout=5.0):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if condition():
            return True
        time.sleep(0.02)
    return bool(condition())


@pytest.mark.skipif(os.name != 'posix', reason='POSIX process group required')
def test_actual_process_completion_and_bounded_output():
    done = run_supervised([sys.executable, '-c', 'print("hello")'], timeout=3)
    assert done.returncode == 0 and done.stdout == 'hello\n'
    assert done.stderr == '' and not done.stdout_truncated


@pytest.mark.skipif(os.name != 'posix', reason='POSIX process group required')
def test_pre_cancel_never_spawns(tmp_path):
    stop = threading.Event()
    stop.set()
    with pytest.raises(ScanCancelled):
        run_supervised([sys.executable, '-c', 'print("hello")'], timeout=3, cancel_event=stop)


@pytest.mark.skipif(os.name != 'posix', reason='POSIX process group required')
def test_cancellation_terminates_real_process(tmp_path):
    marker = tmp_path / 'started'
    stop = threading.Event()
    code = ('import pathlib,sys,time;pathlib.Path(sys.argv[1]).write_text("started");'
            'time.sleep(90)')
    with ThreadPoolExecutor(max_workers=1) as pool:
        result = pool.submit(run_supervised, [sys.executable, '-c', code, str(marker)],
                             timeout=30, cancel_event=stop, poll_seconds=0.03, term_grace_seconds=0.1)
        assert _until(marker.exists)
        stop.set()
        with pytest.raises(ScanCancelled):
            result.result(timeout=5)


@pytest.mark.skipif(os.name != 'posix', reason='POSIX process group required')
def test_sigkill_escalation_for_ignoring_sigterm(tmp_path):
    marker = tmp_path / 'pid'
    stop = threading.Event()
    code = ('import signal, pathlib, sys, time;'
            'signal.signal(signal.SIGTERM, signal.SIG_IGN);'
            'pathlib.Path(sys.argv[1]).write_text(str(__import__("os").getpid()));'
            'time.sleep(100)')
    with ThreadPoolExecutor(max_workers=1) as pool:
        future = pool.submit(run_supervised, [sys.executable, '-c', code, str(marker)],
                             timeout=20, cancel_event=stop, poll_seconds=0.02, term_grace_seconds=0.12)
        assert _until(marker.exists)
        pid = int(marker.read_text())
        stop.set()
        with pytest.raises(ScanCancelled):
            future.result(timeout=8)
        with pytest.raises(ProcessLookupError):
            os.kill(pid, 0)


@pytest.mark.skipif(os.name != 'posix', reason='POSIX process group required')
def test_timeout_kills_real_child(tmp_path):
    marker = tmp_path / 'started'
    code = ('import pathlib,sys,time;pathlib.Path(sys.argv[1]).write_text("x");time.sleep(30)')
    with pytest.raises(TimeoutError):
        run_supervised([sys.executable, '-c', code, str(marker)], timeout=1.5,
                       poll_seconds=0.03, term_grace_seconds=0.1)
    assert marker.exists()


@pytest.mark.skipif(os.name != 'posix', reason='POSIX process group required')
def test_output_bound_drains_without_deadlock():
    script = 'import sys;sys.stdout.write("X"*500000);sys.stderr.write("E"*500000)'
    result = run_supervised([sys.executable, '-c', script], timeout=5,
                            max_output_bytes=2048, poll_seconds=0.02)
    assert len(result.stdout) == 2048 and len(result.stderr) == 2048
    assert result.stdout_truncated and result.stderr_truncated


def test_invalid_arguments_rejected_before_subprocess():
    with pytest.raises(ValueError):
        run_supervised([], timeout=2)
    with pytest.raises(ValueError):
        run_supervised([sys.executable, 'bad\x00arg'], timeout=2)
    with pytest.raises(ValueError):
        run_supervised([sys.executable], timeout=0)


def test_repository_fencing_inspector(tmp_path):
    repo = Repository(tmp_path / 'repo.sqlite')
    repo.add_target('https://example.test', authorized=True)
    job = repo.create_job('https://example.test', 'demo')
    claimed = repo.claim_next_scan_job('worker-a', lease_seconds=5)
    assert claimed.id == job.id
    assert repo.inspect_scan_execution(job.id, 'worker-a', 1) == 'active'
    assert repo.inspect_scan_execution(job.id, 'worker-a', 2) == 'lost'
    assert repo.inspect_scan_execution(job.id, 'worker-b', 1) == 'lost'
    repo.cancel_scan_job(job.id)
    assert repo.inspect_scan_execution(job.id, 'worker-a', 1) == 'cancelled'


@pytest.mark.skipif(os.name != 'posix', reason='POSIX process group required')
def test_real_worker_cancel_interrupts_nuclei_fixture(tmp_path, monkeypatch):
    repo = Repository(tmp_path / 'repo.sqlite')
    repo.add_target('https://example.test', authorized=True)
    job = repo.create_job('https://example.test', 'nuclei')
    started = tmp_path / 'started'
    # Fixed fake executable, no network operations. Executes via Python shebang.
    exe = tmp_path / 'nuclei-offline-fixture'
    exe.write_text('#!' + sys.executable + '\nimport os,time,pathlib\n'
                   f'pathlib.Path({str(started)!r}).write_text("started")\n'
                   'time.sleep(90)\n', encoding='utf-8')
    exe.chmod(0o700)
    registry = AdapterRegistry()
    registry.register(NucleiAdapter(executable=str(exe), timeout=60))
    monkeypatch.setattr('cybersec.runner.default_registry', lambda: registry)
    with ThreadPoolExecutor(max_workers=1) as pool:
        future = pool.submit(run_scan_worker, repo, worker_id='worker', lease_seconds=5,
                             idle_seconds=0.1, max_jobs=1)
        assert _until(started.exists, timeout=8)
        repo.cancel_scan_job(job.id)
        summary = future.result(timeout=8)
    assert summary.claimed == 1 and summary.completed == 0 and summary.failed == 1
    assert repo.get_job(job.id).status == 'cancelled'
    assert not repo.list_scan_artifacts(job.id)
    assert repo.claim_next_scan_job('next-worker') is None


def test_zap_pre_cancel_emits_no_api_request(monkeypatch):
    adapter = ZapPassiveAdapter(api_url='http://127.0.0.1:8080')
    calls = []
    monkeypatch.setattr(adapter, '_api', lambda *args, **kwargs: calls.append(args))
    stop = threading.Event()
    stop.set()
    with pytest.raises(ScanCancelled):
        adapter.run(ScanContext(job_id=1, target_url='https://example.test',
                                tool='zap', options={'cancel_event': stop}))
    assert not calls


def test_zap_cancel_during_poll_stops_local_work(monkeypatch):
    adapter = ZapPassiveAdapter(api_url='http://127.0.0.1:8080', max_wait=10, poll_interval=0.02)
    stop = threading.Event()
    calls = []
    def api(*args, **kwargs):
        calls.append(args)
        if 'recordsToScan' in args:
            stop.set()
            return {'recordsToScan': 25}
        return {}
    monkeypatch.setattr(adapter, '_api', api)
    with pytest.raises(ScanCancelled):
        adapter.run(ScanContext(job_id=1, target_url='https://example.test',
                                tool='zap', options={'cancel_event': stop}))
    assert any('accessUrl' in call for call in calls)
    assert not any('alerts' in call for call in calls)


def test_same_worker_id_stale_attempt_cannot_finish_reclaimed_demo(tmp_path):
    from cybersec.db import connect
    repo = Repository(tmp_path / 'reclaim.sqlite')
    repo.add_target('https://example.test', authorized=True)
    job = repo.create_job('https://example.test', 'demo')
    repo.claim_next_scan_job('same-name', lease_seconds=5)
    with connect(repo.db_path) as db:
        db.execute("UPDATE scan_jobs SET lease_until='2000-01-01T00:00:00.000Z' WHERE id=?", (job.id,))
    repo.claim_next_scan_job('same-name', lease_seconds=5)
    assert repo.inspect_scan_execution(job.id, 'same-name', 1) == 'lost'
    assert repo.inspect_scan_execution(job.id, 'same-name', 2) == 'active'
    with pytest.raises(RuntimeError):
        repo.finish_claimed_scan_job(job.id, 'same-name', attempt=1)
    assert repo.get_job(job.id).status == 'running'
    assert repo.finish_claimed_scan_job(job.id, 'same-name', attempt=2).status == 'completed'


@pytest.mark.skipif(os.name != 'posix', reason='POSIX process group required')
def test_worker_shutdown_event_interrupts_nuclei_fixture(tmp_path, monkeypatch):
    repo = Repository(tmp_path / 'shutdown.sqlite')
    repo.add_target('https://example.test', authorized=True)
    job = repo.create_job('https://example.test', 'nuclei')
    started = tmp_path / 'started'
    exe = tmp_path / 'nuclei-fixture'
    exe.write_text('#!' + sys.executable + '\nimport pathlib,time\n'
                   f'pathlib.Path({str(started)!r}).write_text("ready")\n'
                   'time.sleep(60)\n', encoding='utf-8')
    exe.chmod(0o700)
    registry = AdapterRegistry()
    registry.register(NucleiAdapter(executable=str(exe), timeout=90))
    monkeypatch.setattr('cybersec.runner.default_registry', lambda: registry)
    shutdown = threading.Event()
    with ThreadPoolExecutor(max_workers=1) as pool:
        future = pool.submit(run_scan_worker, repo, worker_id='worker', lease_seconds=5,
                             idle_seconds=0.1, max_jobs=1, stop_event=shutdown)
        assert _until(started.exists, timeout=8)
        shutdown.set()
        summary = future.result(timeout=8)
    assert summary.claimed == 1 and summary.failed == 1
    assert repo.get_job(job.id).status == 'failed'
    assert not repo.list_scan_artifacts(job.id)
    with pytest.raises(PermissionError):
        repo.request_manual_scan_recovery(job.id, acknowledged_by='operator',
                                          external_process_stopped=False)
