"""Ubuntu Server 26.10 independent opt-in host acceptance probes.

Without CYBERSEC_UBUNTU_2610_TESTS=1 these never run. Tests never invoke
ZAP, Nuclei, sqlmap or network targets. Any missing host prerequisite is FAIL
(not a fake PASS) after opt-in.
"""
import os
from pathlib import Path
import pwd
import shutil
import signal
import subprocess
import sys
import time

import pytest
from cybersec.stage64_runtime import audit_host
from cybersec.stage65.broker import KernelCgroupBroker
from cybersec.stage65.host import actual_role_map, exact_enforcing_mac
from cybersec.stage65.ledger import LedgerBlocked
from cybersec.process_identity import observe_process, matches_identity, read_population

pytestmark=pytest.mark.skipif(os.environ.get('CYBERSEC_UBUNTU_2610_TESTS')!='1',
                              reason='Explicit Ubuntu 26.10 opt-in required')


def _host():
    d=audit_host()
    assert d.checks['ubuntu_server_26_10'], f'Wrong host: {d.os_release}'
    assert d.checks['systemd_pid1'] and d.checks['unified_cgroup_v2']
    return d


def _delegated():
    _host()
    value=os.environ.get('CYBERSEC_STAGE65_TEST_DELEGATED_CGROUP','')
    assert value.startswith('/sys/fs/cgroup/') and not Path(value).is_symlink(), 'Privileged lab-delegated cgroup required'
    path=Path(value)
    assert path.is_dir() and (path/'cgroup.kill').is_file()
    return path


def test_real_host_four_uid_pids_and_enforcing_profiles():
    h=_host()
    roles=actual_role_map()
    assert len(set(vars(roles).values()))==5
    assert h.checks['apparmor_kernel_enabled']
    assert Path('/proc/self/attr/current').exists()
    assert 'unconfined' not in Path('/proc/self/attr/current').read_text()


def test_real_proc_pid_reuse_identity_negative():
    _host()
    myself=observe_process(os.getpid())
    assert matches_identity(myself)
    from dataclasses import replace
    assert not matches_identity(replace(myself,start_ticks=myself.start_ticks+1))


def test_preexec_rejects_unavailable_broker_policy():
    _host()
    from cybersec.stage65.host import HostAdmission
    h=HostAdmission(expected_profile='cybersec-broker',fixed_cgroup=_delegated(),
                    installed_unit=Path('/etc/systemd/system/cybersec-broker.service'),
                    approved_policy_digest='0'*64)
    with pytest.raises(LedgerBlocked,match='BLOCKED|missing|identity|OS|Ubuntu|AppArmor|unavailable|systemd|not'):
        h.check(roles=actual_role_map())


def test_real_cgroup_kill_nested_setsid_double_fork(tmp_path):
    parent=_delegated()
    runner=KernelCgroupBroker(parent)
    # Safe Python-only fixture: child daemonizes, then waits; broker must NOT
    # report a clean return, and must kill its detached descendant via cgroup.kill.
    script=tmp_path/'fixture.py'
    script.write_text('import os,time\np=os.fork()\nif p: os._exit(0)\nos.setsid()\np=os.fork()\nif p: os._exit(0)\nfor fd in (0,1,2):\n try: os.close(fd)\n except OSError: pass\ntime.sleep(30)\n')
    with pytest.raises(LedgerBlocked):
        runner.run('stage65-doublefork',[sys.executable,str(script)],timeout=4)
    assert not (parent/'scan-stage65-doublefork').exists()


def test_concurrent_broker_scopes_and_restart_cleanup(tmp_path):
    parent=_delegated()
    runner=KernelCgroupBroker(parent)
    # Real supervisor restart proof is gated by independent acceptance log;
    # only this local kernel cleanup primitive is exercised here.
    from concurrent.futures import ThreadPoolExecutor
    def task(n):
        return runner.run(f'stage65-concurrent-{n}',[sys.executable,'-c','print(123)'],timeout=8)
    with ThreadPoolExecutor(max_workers=3) as pool:
        results=list(pool.map(task,range(3)))
    assert all(code==0 and out.strip()==b'123' for code,out,_ in results)
    assert runner.recover_orphans()==[]


def test_four_real_uid_processes_have_distinct_kernel_identities():
    _host()
    assert os.geteuid()==0, 'Root-controlled opt-in fixture required for cross-UID setuid'
    roles=actual_role_map()
    runuser=shutil.which('runuser')
    assert runuser, 'runuser missing from independent host'
    actual={}
    for role in ('worker','attester','witness','publisher'):
        account='cybersec-'+role
        completed=subprocess.run([runuser,'-u',account,'--','/usr/bin/id','-u'],
                                 capture_output=True,text=True,timeout=8,check=False)
        assert completed.returncode==0, f'Cannot execute UID fixture for {role}: {completed.stderr}'
        actual[role]=int(completed.stdout.strip())
        assert actual[role]==getattr(roles,role)
    assert len(set(actual.values()))==4


@pytest.mark.skipif(os.environ.get('CYBERSEC_STAGE65_DESTRUCTIVE_TESTS')!='1',
                    reason='Real PID1 SIGKILL/restart requires separate destructive-test opt-in')
def test_real_systemd_pid1_sigkill_and_service_restart(tmp_path):
    _host()
    assert os.geteuid()==0, 'Root is required to create isolated transient unit'
    assert shutil.which('systemd-run') and shutil.which('systemctl')
    unit=f'cybersec-stage65-fixture-{os.getpid()}.service'
    script=tmp_path/'life.py'
    script.write_text('import os,time\nwhile True: time.sleep(0.2)\n')
    command=['systemd-run','--unit='+unit,'--collect',
        '--property=Restart=on-failure','--property=RestartSec=1s',
        '--property=KillMode=control-group','--property=SendSIGKILL=yes',
        '--property=Type=exec',sys.executable,str(script)]
    started=subprocess.run(command,capture_output=True,text=True,timeout=10)
    assert started.returncode==0, started.stderr
    def show():
        p=subprocess.run(['systemctl','show',unit,
            '--property=MainPID','--property=NRestarts','--property=ControlGroup'],
            capture_output=True,text=True,timeout=7)
        assert p.returncode==0, p.stderr
        return dict(line.split('=',1) for line in p.stdout.splitlines() if '=' in line)
    try:
        first=show()
        deadline=time.monotonic()+10
        while int(first.get('MainPID','0'))<=1 and time.monotonic()<deadline:
            time.sleep(.1);first=show()
        old_pid=int(first['MainPID'])
        assert old_pid>1
        old=observe_process(old_pid)
        os.kill(old_pid,signal.SIGKILL)
        deadline=time.monotonic()+18
        second=show()
        while (int(second.get('MainPID','0')) in (0,old_pid) or
               int(second.get('NRestarts','0')) < 1) and time.monotonic()<deadline:
            time.sleep(.2);second=show()
        new_pid=int(second.get('MainPID','0'))
        assert new_pid>1 and new_pid!=old_pid and int(second['NRestarts'])>=1
        assert not matches_identity(old), 'SIGKILLed process reused its identity'
        assert second.get('ControlGroup','').startswith('/'), 'Systemd did not own a service cgroup'
        assert observe_process(new_pid).cgroup==second['ControlGroup']
    finally:
        subprocess.run(['systemctl','stop',unit],capture_output=True,timeout=10)
        subprocess.run(['systemctl','reset-failed',unit],capture_output=True,timeout=10)


@pytest.mark.skipif(os.environ.get('CYBERSEC_STAGE65_MAC_NEGATIVE_TESTS')!='1',
                    reason='Kernel AppArmor denial probes require separate opt-in')
def test_actual_kernel_audit_denial_for_legacy_same_uid():
    _host()
    fixture=os.environ.get('CYBERSEC_STAGE65_LEGACY_NEGATIVE_FIXTURE','')
    assert fixture.startswith('/') and Path(fixture).is_file()
    checkpoint=subprocess.run(['date','+%Y-%m-%d %H:%M:%S'],capture_output=True,text=True,check=True).stdout.strip()
    completed=subprocess.run([fixture],capture_output=True,timeout=15,check=False)
    assert completed.returncode!=0, 'Same-UID legacy bypass succeeded'
    audit=subprocess.run(['journalctl','-k','--since',checkpoint,'--no-pager'],
                         capture_output=True,text=True,timeout=10,check=False)
    assert audit.returncode==0 and 'apparmor="DENIED"' in audit.stdout and \
           'cybersec-worker' in audit.stdout, 'No independent kernel audit denial correlated to worker profile'
