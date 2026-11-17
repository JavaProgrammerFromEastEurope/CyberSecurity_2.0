"""Opt-in Ubuntu Server checks; only local Python fixtures, never real scanners.

Run on Ubuntu Server with:
CYBERSEC_UBUNTU_SERVER_TESTS=1 python -W error::ResourceWarning -W error::DeprecationWarning -m pytest -q tests/integration/test_stage63_ubuntu.py
"""
from __future__ import annotations

import os
from pathlib import Path
import signal
import subprocess
import sys
import time

import pytest

from cybersec.process_supervisor import ProcessCancelled, ProcessSupervisor
from cybersec.repository import Repository
from cybersec.db import connect

pytestmark = pytest.mark.skipif(
    sys.platform != 'linux' or os.getenv('CYBERSEC_UBUNTU_SERVER_TESTS') != '1',
    reason='explicit opt-in on Ubuntu Server required',
)


def _wait(path: Path, seconds=4):
    end = time.monotonic() + seconds
    while time.monotonic() < end:
        if path.exists():
            return True
        time.sleep(.03)
    return False


def _running(pid: int) -> bool:
    try:
        state = Path(f'/proc/{pid}/stat').read_text().split(') ')[1].split()[0]
        return state not in {'Z', 'X'}
    except FileNotFoundError:
        return False


def test_ubuntu_kills_python_fixture_group(tmp_path):
    """A parent and a same-PGID descendant must stop on bounded cancellation."""
    child_pid = tmp_path / 'child.pid'
    parent_pid = tmp_path / 'parent.pid'
    script = (
        'import subprocess,sys,time,signal,os,pathlib; '
        'signal.signal(signal.SIGTERM,signal.SIG_IGN); '
        'c=subprocess.Popen([sys.executable,"-c",'
        '"import signal,time;signal.signal(signal.SIGTERM,signal.SIG_IGN);time.sleep(20)"]); '
        f'pathlib.Path({str(child_pid)!r}).write_text(str(c.pid)); '
        f'pathlib.Path({str(parent_pid)!r}).write_text(str(os.getpid())); '
        'time.sleep(20)'
    )
    try:
        with pytest.raises(ProcessCancelled):
            ProcessSupervisor(grace_seconds=.2, poll_seconds=.05).run(
                [sys.executable, '-c', script], timeout=8,
                cancelled=lambda: child_pid.exists() and parent_pid.exists())
        assert _wait(child_pid), 'python fixture never started'
        assert not _running(int(parent_pid.read_text())), 'group leader still running'
        assert not _running(int(child_pid.read_text())), 'same-group child still running'
    finally:
        # Cleanup is mandatory even for a failed test to avoid orphan fixtures.
        if parent_pid.exists():
            try:
                os.killpg(int(parent_pid.read_text()), signal.SIGKILL)
            except ProcessLookupError:
                pass
        if child_pid.exists() and _running(int(child_pid.read_text())):
            os.kill(int(child_pid.read_text()), signal.SIGKILL)


def test_ubuntu_manual_recovery_after_lease_expiry(tmp_path):
    repo = Repository(tmp_path / 'crash.sqlite')
    repo.add_target('https://example.test', authorized=True)
    job = repo.create_job('https://example.test', 'nuclei')
    repo.claim_next_scan_job('worker-before-crash', lease_seconds=5)
    # Simulate worker crash/expired lease via SQLite metadata; no scanner started.
    with connect(repo.db_path) as db:
        db.execute("UPDATE scan_jobs SET lease_until='2000-01-01T00:00:00.000Z' WHERE id=?", (job.id,))
    assert repo.claim_next_scan_job('worker-after-crash', lease_seconds=5) is None
    assert repo.get_job(job.id).status == 'failed'
    with pytest.raises(PermissionError):
        repo.request_manual_scan_recovery(job.id, acknowledged_by='operator',
                                          external_process_stopped=False)
    replacement = repo.request_manual_scan_recovery(job.id, acknowledged_by='operator',
                                                    external_process_stopped=True)
    assert replacement.id != job.id and replacement.status == 'queued'
