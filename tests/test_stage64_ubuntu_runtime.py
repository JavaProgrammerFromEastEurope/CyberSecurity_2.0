"""Pure Python/local fixture tests: no scanner binaries or network targets."""
from __future__ import annotations

import json
import os
from pathlib import Path
import signal
import subprocess
import sys
import time

import pytest

from cybersec.production_admission import ProductionAdmissionDenied, require_production_admission
from cybersec import stage64_runtime as runtime
from cybersec.process_identity import (ProcessIdentity, matches_identity, observe_process,
                                      parse_cgroup, parse_start_ticks, read_population)
from cybersec.process_supervisor import ProcessCancelled, ProcessSupervisor
from cybersec.runner import JobRunner
from cybersec.scan_worker import run_scan_worker
from cybersec.scanners import ScanContext, SqlmapConfirmationAdapter, NucleiAdapter, ZapPassiveAdapter


def test_host_preflight_readonly_no_go_and_no_credentials():
    report = runtime.audit_host().to_dict()
    assert report['schema'] == 'cybersec.stage64.host-inventory.v1'
    assert report['status'] == 'BLOCKED/NO-GO'
    assert report['production_admitted'] is False
    assert report['checks']['independent_os_mac_negative_tests'] is False
    assert report['checks']['independent_admission_authority'] is False
    assert report['blockers']
    assert 'private_key' not in json.dumps(report)


def test_cli_preflight_exit3(monkeypatch, capsys):
    # No service or external scanner is called by this safe CLI.
    from cybersec.cli import main
    rc = main(['host-preflight'])
    assert rc == 3
    assert json.loads(capsys.readouterr().out)['production_admitted'] is False


def test_prod_admission_never_uses_env_as_permission(monkeypatch):
    monkeypatch.setenv('CYBERSEC_EXECUTION_MODE', 'production')
    monkeypatch.setenv('CYBERSEC_PROCESS_SUPERVISION', '1')
    monkeypatch.setenv('INVOCATION_ID', 'a'*32)
    monkeypatch.setenv('CYBERSEC_PRODUCTION_ADMITTED', '1')
    with pytest.raises(ProductionAdmissionDenied, match='BLOCKED/NO-GO'):
        require_production_admission(action='fixture')
    with pytest.raises(ProductionAdmissionDenied):
        NucleiAdapter(executable='/not-real/nuclei').run(ScanContext(2,'https://example.test','nuclei'))
    with pytest.raises(ProductionAdmissionDenied):
        ZapPassiveAdapter().run(ScanContext(2,'https://example.test','zap'))
    with pytest.raises(ProductionAdmissionDenied):
        SqlmapConfirmationAdapter(executable='/not-real/sqlmap').run(ScanContext(2,'https://example.test','sqlmap'))


def test_prod_blocks_direct_runner_and_worker_without_opening_db(monkeypatch, tmp_path):
    from cybersec.repository import Repository
    repo = Repository(tmp_path/'empty.sqlite')
    monkeypatch.setenv('CYBERSEC_RUNTIME_MODE', 'production')
    with pytest.raises(ProductionAdmissionDenied):
        JobRunner(repo).run(999)
    with pytest.raises(ProductionAdmissionDenied):
        run_scan_worker(repo,worker_id='blocked',max_jobs=1)
    monkeypatch.delenv('CYBERSEC_RUNTIME_MODE')


def test_development_demo_still_works(monkeypatch, tmp_path):
    from cybersec.repository import Repository
    monkeypatch.delenv('CYBERSEC_EXECUTION_MODE', raising=False)
    monkeypatch.delenv('CYBERSEC_RUNTIME_MODE', raising=False)
    repo = Repository(tmp_path/'demo.sqlite')
    repo.add_target('https://example.test',authorized=True)
    job = repo.create_job('https://example.test','demo')
    assert JobRunner(repo).run(job.id).status == 'completed'


def test_proc_parser_cgroup_and_pid_reuse(tmp_path):
    stat = '900 (odd ) process) S ' + ' '.join(['0']*18+['4512']+['0']*4)
    assert parse_start_ticks(stat) == 4512
    assert parse_cgroup('0::/system.slice/work.service\n') == '/system.slice/work.service'
    with pytest.raises(ValueError):
        parse_cgroup('0::/ok\n0::/other\n')
    with pytest.raises(ValueError):
        parse_cgroup('0::/../escape\n')
    root = tmp_path/'proc'
    (root/'900').mkdir(parents=True)
    (root/'900'/'stat').write_text(stat)
    (root/'900'/'cgroup').write_text('0::/test.slice\n')
    identity = observe_process(900,proc_root=root)
    assert identity.start_ticks == 4512
    assert matches_identity(identity,proc_root=root)
    (root/'900'/'stat').write_text(stat.replace('4512','4513'))
    assert not matches_identity(identity,proc_root=root)


def test_cgroup_population_is_readonly(tmp_path):
    assert read_population(tmp_path) is None
    (tmp_path/'cgroup.events').write_text('populated 1\nfrozen 0\n')
    assert read_population(tmp_path) is True
    (tmp_path/'cgroup.events').write_text('populated 0\n')
    assert read_population(tmp_path) is False
    (tmp_path/'cgroup.events').write_text('populated huh\n')
    assert read_population(tmp_path) is None


def test_preflight_binary_version_parsing(monkeypatch):
    # Keep compatibility probe read-only and bounded; no scanner subprocesses.
    monkeypatch.setattr(runtime.shutil,'which', lambda name:'/usr/bin/systemctl')
    class Result:
        returncode=0
        stdout='systemd 261 (261.3-0ubuntu3)\n'
    monkeypatch.setattr(runtime.subprocess,'run', lambda *args,**kwargs: Result())
    assert runtime._systemd_version() == 261
    Result.stdout='systemctl fake 999\n'
    assert runtime._systemd_version() is None


@pytest.mark.skipif(os.name != 'posix', reason='POSIX only')
def test_local_python_sigterm_process_group(tmp_path):
    ready = tmp_path/'ready'
    script = ('import pathlib,time; '
              f'pathlib.Path({str(ready)!r}).write_text("ok"); time.sleep(20)')
    with pytest.raises(ProcessCancelled):
        ProcessSupervisor(grace_seconds=.2,poll_seconds=.03).run(
            [sys.executable,'-c',script],timeout=5,cancelled=ready.exists)
    assert ready.exists()


@pytest.mark.skipif(os.name != 'posix', reason='POSIX only')
def test_local_python_sigkill_escalation(tmp_path):
    ready = tmp_path/'ready'
    script = ('import pathlib,time,signal; '
              'signal.signal(signal.SIGTERM, signal.SIG_IGN); '
              f'pathlib.Path({str(ready)!r}).write_text("ok"); time.sleep(20)')
    with pytest.raises(ProcessCancelled):
        ProcessSupervisor(grace_seconds=.12,poll_seconds=.03).run(
            [sys.executable,'-c',script],timeout=5,cancelled=ready.exists)
    assert ready.exists()


def test_legacy_bypass_not_claimed_by_inventory():
    report = runtime.audit_host()
    assert 'same-UID legacy scanner and interpreter confinement under kernel MAC' in report.unproven
    assert report.production_admitted is False
    assert 'independent_os_mac_negative_tests' in report.blockers

@pytest.mark.skipif(os.name != 'posix', reason='POSIX only')
def test_process_group_escalation_leaves_no_running_python_descendant(tmp_path):
    """A same-process-group Python grandchild is stopped with SIGKILL."""
    child_file = tmp_path / 'child.pid'
    script = (
        'import pathlib,subprocess,sys,time; '
        'c=subprocess.Popen([sys.executable,"-c",'
        '"import signal,time;signal.signal(signal.SIGTERM,signal.SIG_IGN);time.sleep(20)"]); '
        f'pathlib.Path({str(child_file)!r}).write_text(str(c.pid)); '
        'time.sleep(20)'
    )
    def still_running(pid):
        try:
            raw=Path(f'/proc/{pid}/stat').read_text()
            return raw.rsplit(')',1)[1].split()[0] not in ('Z','X')
        except FileNotFoundError:
            return False
    try:
        with pytest.raises(ProcessCancelled):
            ProcessSupervisor(grace_seconds=.15,poll_seconds=.03).run(
                [sys.executable,'-c',script],timeout=5,cancelled=child_file.exists)
        assert child_file.is_file()
        child_pid=int(child_file.read_text())
        deadline=time.monotonic()+1.0
        while still_running(child_pid) and time.monotonic()<deadline:
            time.sleep(.03)
        assert not still_running(child_pid), 'same-group descendant escaped SIGKILL'
    finally:
        if child_file.exists() and still_running(int(child_file.read_text())):
            os.kill(int(child_file.read_text()),signal.SIGKILL)


@pytest.mark.skipif(os.name != 'posix', reason='POSIX only')
def test_process_restart_requires_new_identity():
    """Local fixture restart (NOT a systemd restart acceptance)."""
    def launch():
        return subprocess.Popen([sys.executable,'-c','import time;time.sleep(20)'],
                                start_new_session=True)
    first=launch()
    try:
        initial=observe_process(first.pid)
    finally:
        first.kill()
        first.wait(timeout=4)
    assert not matches_identity(initial)
    second=launch()
    try:
        after=observe_process(second.pid)
        assert after != initial
        assert matches_identity(after)
    finally:
        second.kill()
        second.wait(timeout=4)
    assert not matches_identity(after)


def test_sqlmap_blocked_production_does_not_consume_approval(monkeypatch):
    from cybersec.sqlmap_gate import execute_approved_confirmation
    monkeypatch.setenv('CYBERSEC_EXECUTION_MODE', 'production')
    class NeverConsume:
        def claim_sqlmap_confirmation(self, confirmation_id):
            pytest.fail('Production approval was consumed before mandatory admission')
    with pytest.raises(ProductionAdmissionDenied, match='BLOCKED/NO-GO'):
        execute_approved_confirmation(NeverConsume(), 123)


def test_release_version_consistent_with_package_metadata():
    from cybersec import __version__
    from pathlib import Path
    import tomllib
    import cybersec
    root=Path(cybersec.__file__).resolve().parents[2]
    metadata=tomllib.loads((root/'pyproject.toml').read_text(encoding='utf-8'))
    assert __version__ == metadata['project']['version']
    # Stage 64 baseline remains supported; cumulative releases advance version.
    assert tuple(int(part) for part in __version__.split('.')) >= (2, 44, 0)
