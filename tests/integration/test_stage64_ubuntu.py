"""Opt-in Ubuntu 26.10 integration diagnostics. No third-party scanners.

These tests intentionally fail if host prerequisites are absent; opt-in only
with CYBERSEC_UBUNTU_2610_TESTS=1 on an operator-controlled Ubuntu host.
"""
from __future__ import annotations

import os
import pathlib
import subprocess
import sys
import time

import pytest

from cybersec.stage64_runtime import audit_host
from cybersec.process_identity import matches_identity, observe_process
from cybersec.process_supervisor import ProcessCancelled, ProcessSupervisor

pytestmark = pytest.mark.skipif(
    not (sys.platform == 'linux' and os.getenv('CYBERSEC_UBUNTU_2610_TESTS') == '1'),
    reason='Ubuntu Server 26.10 opt-in only; no external scanners',
)


def test_real_host_versions_service_and_cgroup():
    report = audit_host()
    for check in ('ubuntu_server_26_10','python_3_14','openssl_4',
                  'systemd_261_or_newer','systemd_pid1','unified_cgroup_v2',
                  'cgroup_kill_available','apparmor_kernel_enabled',
                  'four_separate_service_uids'):
        assert report.checks[check], f'Host requirement absent: {check}'
    assert not report.production_admitted  # even an otherwise ready host cannot grant a permit


def test_python_local_service_process_identity(tmp_path):
    ready=tmp_path/'child.pid'
    code=('import os,pathlib,time; '
          f'pathlib.Path({str(ready)!r}).write_text(str(os.getpid())); '
          'time.sleep(20)')
    p=subprocess.Popen([sys.executable,'-c',code],start_new_session=True)
    try:
        for _ in range(100):
            if ready.is_file(): break
            time.sleep(.025)
        assert ready.is_file()
        identity=observe_process(p.pid)
        assert identity.pid==p.pid and matches_identity(identity)
    finally:
        import signal
        os.killpg(p.pid,signal.SIGKILL)
        p.wait(timeout=5)
    assert not matches_identity(identity)


def test_python_timeout_sigkill_and_no_orphans(tmp_path):
    ready = tmp_path / 'ready'
    code = ('import signal,time,pathlib; '
            'signal.signal(signal.SIGTERM,signal.SIG_IGN); '
            f'pathlib.Path({str(ready)!r}).touch();time.sleep(20)')
    with pytest.raises(ProcessCancelled):
        ProcessSupervisor(grace_seconds=.15,poll_seconds=.03).run(
            [sys.executable,'-c',code],timeout=6,cancelled=ready.exists)
    assert ready.exists()


def test_admission_still_no_go_even_after_opt_in():
    report=audit_host()
    assert report.status=='BLOCKED/NO-GO'
    assert not report.checks['independent_os_mac_negative_tests']
    assert not report.checks['hardware_monotonic_recovery_permit']


def test_ubuntu_doublefork_setsid_remains_in_service_cgroup(tmp_path):
    """Demonstrate that setsid/double-fork alone cannot escape cgroup v2.

    This does NOT prove an attacker cannot write cgroup.procs. A separate
    externally administered MAC negative test remains mandatory.
    """
    import signal
    marker=tmp_path/'grandchild.pid'
    script = (
        'import os,sys,pathlib,time; '
        'p=os.fork(); '
        'os._exit(0) if p else None; '
        'os.setsid(); '
        'g=os.fork(); '
        'os._exit(0) if g else None; '
        f'pathlib.Path({str(marker)!r}).write_text(str(os.getpid())); '
        'time.sleep(20)'
    )
    origin=observe_process(os.getpid())
    initial=subprocess.Popen([sys.executable,'-c',script],
                             stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL,
                             stderr=subprocess.DEVNULL, start_new_session=True)
    survivor=None
    try:
        initial.wait(timeout=3)
        for _ in range(120):
            if marker.is_file(): break
            time.sleep(.025)
        assert marker.exists(), 'double-fork fixture was not ready'
        survivor=int(marker.read_text())
        detached=observe_process(survivor)
        assert detached.cgroup==origin.cgroup
        assert os.getsid(survivor)!=os.getsid(os.getpid())
    finally:
        if survivor is not None:
            try: os.kill(survivor,signal.SIGKILL)
            except ProcessLookupError: pass
        if initial.poll() is None:
            initial.kill()
            initial.wait(timeout=3)


def test_ubuntu_systemd_manager_property_inventory():
    """Read-only manager property assertions; no systemd units started."""
    command=['systemctl','show','--no-pager',
             '--property=Version,ControlGroup,MainPID,ActiveState,FragmentPath,KillMode',
             'cybersec-scanner-worker.service']
    result=subprocess.run(command,capture_output=True,text=True,timeout=5,check=False)
    assert result.returncode==0, result.stderr
    props=dict(line.split('=',1) for line in result.stdout.splitlines() if '=' in line)
    assert props.get('KillMode')=='control-group'
    assert props.get('FragmentPath','').startswith('/etc/systemd/system/')
    # Stage64 intentionally blocks startup in ExecStartPre. Active state does
    # NOT imply authorization; do not use these properties as an admission gate.
