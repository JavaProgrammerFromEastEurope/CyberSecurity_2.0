"""Stage 62: negative gates and real local pre-exec barrier; no network scanning."""
from __future__ import annotations

import base64
import json
import os
import pathlib
import subprocess
import sys
import threading
from datetime import datetime, timedelta, timezone
from unittest.mock import patch

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives import serialization

from cybersec.cgroup_containment import (
    CgroupV2Executor, ContainmentBlocked, readonly_host_preflight,
    verify_attached_process,
)
from cybersec.lab_authorization import (
    LabAuthorizationBlocked, require_loopback_ip, verify_lab_ticket,
)
from cybersec.repository import Repository
from cybersec.runner import JobRunner
from cybersec.scan_worker import run_scan_worker
from cybersec.scanners import NucleiAdapter, ScanContext, ZapPassiveAdapter


def ticket_fixture():
    key = Ed25519PrivateKey.generate()
    public = key.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
    now = datetime.now(timezone.utc)
    payload = {
        'schema':'cybersec.lab-attempt.v1','purpose':'authorized-loopback-lab',
        'job_id':8,'attempt':1,'tool':'nuclei','target_url':'http://127.0.0.1:8181/',
        'issued_utc':(now-timedelta(minutes=1)).isoformat().replace('+00:00','Z'),
        'expires_utc':(now+timedelta(minutes=3)).isoformat().replace('+00:00','Z'),
        'nonce':'b'*32,
    }
    def sign(p, signer=key):
        body=json.dumps(p,sort_keys=True,separators=(',',':'),ensure_ascii=False).encode()
        return {'payload':p,'signature':base64.b64encode(signer.sign(body)).decode()}
    return public, payload, sign


def test_real_host_preflight_is_review_only():
    report=readonly_host_preflight()
    assert report.status == 'BLOCKED/NO-GO'
    assert report.production_admission is False
    assert 'systemd_pid1' in report.checks
    assert 'cgroup_kill' in report.checks
    assert 'enforcing_mac_profile' in report.checks


def test_cgroup_executor_refuses_without_writable_delegation(tmp_path):
    exe=CgroupV2Executor(tmp_path)
    marker=tmp_path/'unexpected'
    with pytest.raises(ContainmentBlocked):
        exe.run([sys.executable,'-c',f'open({str(marker)!r},"w").write("BAD")'],timeout=1)
    assert not marker.exists()


def test_cgroup_executor_rejects_traversal_and_symlink(tmp_path):
    link=tmp_path/'linked'
    link.symlink_to('/sys/fs/cgroup')
    with pytest.raises(ContainmentBlocked):
        CgroupV2Executor(link)._preflight()
    with pytest.raises(ContainmentBlocked):
        CgroupV2Executor(pathlib.Path('/sys/fs/cgroup'))._preflight()


def test_before_exec_gate_rejects_pid_reuse(monkeypatch):
    monkeypatch.setattr('cybersec.cgroup_containment._process_starttime',lambda pid:'100' if pid != -2 else '200')
    monkeypatch.setattr('cybersec.cgroup_containment._cgroup_for',lambda pid:'/delegated/scan-abc')
    verify_attached_process(33,starttime='100',exact_cgroup='/delegated/scan-abc')
    with pytest.raises(ContainmentBlocked):
        verify_attached_process(33,starttime='99',exact_cgroup='/delegated/scan-abc')
    monkeypatch.setattr('cybersec.cgroup_containment._cgroup_for',lambda pid:'/untrusted')
    with pytest.raises(ContainmentBlocked):
        verify_attached_process(33,starttime='100',exact_cgroup='/delegated/scan-abc')


@pytest.mark.skipif(sys.platform!='linux',reason='Linux trampoline check')
@pytest.mark.parametrize('payload',[b'',b'0',b'11',b'1'])
def test_real_trampoline_never_execs_on_bad_gate(tmp_path,payload):
    marker=tmp_path/'forbidden'
    read,write=os.pipe()
    try:
        with subprocess.Popen([
            sys.executable,'-m','cybersec.cgroup_trampoline',
            '--gate-fd',str(read),'--expected-cgroup','/nonexistent-cybersec-test',
            '--',sys.executable,'-c',f'open({str(marker)!r},"w").write("bad")',
        ],pass_fds=(read,),stdin=subprocess.DEVNULL,stdout=subprocess.PIPE,
           stderr=subprocess.PIPE) as proc:
            os.close(read)
            read=-1
            if payload:
                os.write(write,payload)
            os.close(write)
            write=-1
            stdout,stderr=proc.communicate(timeout=5)
            assert proc.returncode == 125
            assert stdout == b'' and stderr == b''
    finally:
        if read >= 0: os.close(read)
        if write >= 0: os.close(write)
    assert not marker.exists()


@pytest.mark.parametrize('target',[ 'http://localhost:8000/', 'http://example.com/',
    'https://192.0.2.2/', 'http://user:pass@127.0.0.1',
    'https://127.0.0.1/#fragment', 'http://[2001:db8::1]/'])
def test_authorized_lab_requires_ip_literal_loopback(target):
    with pytest.raises(LabAuthorizationBlocked):
        require_loopback_ip(target)


@pytest.mark.parametrize('target',['http://127.0.0.1:8181/','https://[::1]:443/'])
def test_loopback_literals_are_allowed_for_signed_lab_purpose(target):
    require_loopback_ip(target)


def test_externally_signed_ticket_exact_job_and_attempt():
    pub,payload,sign=ticket_fixture()
    t=sign(payload)
    assert verify_lab_ticket(ticket=t,pinned_public_key=pub,job_id=8,
            attempt=1,tool='nuclei',target_url=payload['target_url'])['job_id']==8
    for job,attempt,tool,url in [(9,1,'nuclei',payload['target_url']),
                                  (8,2,'nuclei',payload['target_url']),
                                  (8,1,'zap',payload['target_url']),
                                  (8,1,'nuclei','http://127.0.0.1:9999/')]:
        with pytest.raises(LabAuthorizationBlocked):
            verify_lab_ticket(ticket=t,pinned_public_key=pub,job_id=job,
                    attempt=attempt,tool=tool,target_url=url)


def test_signature_swap_replay_expiry_and_extension_refused():
    pub,payload,sign=ticket_fixture()
    forged=sign(dict(payload,job_id=9))
    forged['payload']['job_id']=8
    with pytest.raises(LabAuthorizationBlocked):
        verify_lab_ticket(ticket=forged,pinned_public_key=pub,job_id=8,
                          attempt=1,tool='nuclei',target_url=payload['target_url'])
    for change in ({'nonce':'nope'}, {'target_url':'https://other.test'},
                   {'purpose':'generic-scan'}, {'extra':'unsafe'}):
        bad=sign(dict(payload,**change))
        with pytest.raises(LabAuthorizationBlocked):
            verify_lab_ticket(ticket=bad,pinned_public_key=pub,job_id=8,
                    attempt=1,tool='nuclei',target_url=payload['target_url'])
    expired=sign(dict(payload,expires_utc='2000-01-01T00:00:00Z'))
    with pytest.raises(LabAuthorizationBlocked):
        verify_lab_ticket(ticket=expired,pinned_public_key=pub,job_id=8,
                attempt=1,tool='nuclei',target_url=payload['target_url'])
    with pytest.raises(LabAuthorizationBlocked):
        verify_lab_ticket(ticket=sign(payload),pinned_public_key=b'wrong',job_id=8,
                attempt=1,tool='nuclei',target_url=payload['target_url'])


def test_production_direct_legacy_scanner_denied(tmp_path,monkeypatch):
    monkeypatch.setenv('CYBERSEC_EXECUTION_MODE','production')
    repo=Repository(tmp_path/'repo.db')
    repo.add_target('http://127.0.0.1:8181/',authorized=True)
    job=repo.create_job('http://127.0.0.1:8181/','nuclei')
    with pytest.raises(ContainmentBlocked,match='Direct legacy'):
        JobRunner(repo).run(job.id)
    assert repo.get_job(job.id).status=='queued'
    with pytest.raises(ContainmentBlocked,match='Legacy direct'):
        NucleiAdapter(executable='/bin/echo').run(ScanContext(job.id,
            'http://127.0.0.1:8181/','nuclei'))


def test_production_zap_remote_daemon_and_worker_fail_closed(tmp_path,monkeypatch):
    monkeypatch.setenv('CYBERSEC_EXECUTION_MODE','production')
    with pytest.raises(ContainmentBlocked,match='Remote ZAP'):
        ZapPassiveAdapter(api_url='http://127.0.0.1:1234').run(
            ScanContext(2,'http://127.0.0.1:8181/','zap'))
    repo=Repository(tmp_path/'repo.db')
    repo.add_target('http://127.0.0.1:8181/',authorized=True)
    job=repo.create_job('http://127.0.0.1:8181/','nuclei')
    with patch('cybersec.stage62_audit.audit_host',return_value={'blockers':['cgroup_kill'], 'unproven':['NO-GO']}):
        with pytest.raises(ContainmentBlocked,match='cgroup_kill'):
            run_scan_worker(repo,worker_id='worker',max_jobs=1)
    assert repo.get_job(job.id).status=='queued'


def test_production_nuclei_rejects_missing_independent_ticket_before_exec(monkeypatch,tmp_path):
    monkeypatch.setenv('CYBERSEC_EXECUTION_MODE','production')
    marker=tmp_path/'unwanted'
    executable=tmp_path/'scanner'
    executable.write_text('#!/bin/sh\ntouch '+str(marker)+'\n')
    executable.chmod(0o700)
    with pytest.raises(LabAuthorizationBlocked):
        NucleiAdapter(executable=str(executable)).run(
            ScanContext(8,'http://127.0.0.1:8181/','nuclei',
                        {'worker_id':'worker','attempt':1,'cancel_event':threading.Event()}))
    assert not marker.exists()


def test_production_even_optimistic_local_host_checks_cannot_grant_permit(tmp_path,monkeypatch):
    monkeypatch.setenv('CYBERSEC_EXECUTION_MODE','production')
    repo=Repository(tmp_path/'r.sqlite')
    repo.add_target('http://127.0.0.1:8080/',authorized=True)
    job=repo.create_job('http://127.0.0.1:8080/','nuclei')
    with patch('cybersec.stage62_audit.audit_host',return_value={
         'blockers':[],'unproven':['independent MAC cannot be inferred']}):
        with pytest.raises(ContainmentBlocked,match='independent MAC'):
            run_scan_worker(repo,worker_id='w',max_jobs=1)
    assert repo.get_job(job.id).status == 'queued'


@pytest.mark.parametrize('escaped_script',[
    'import os; os.setsid(); open("NEVER", "w").write("bad")',
    'import os; os.fork(); os.fork(); open("NEVER", "w").write("bad")',
])
def test_setsids_and_doublefork_fixtures_never_start_without_cgroup(tmp_path, escaped_script):
    # Does not prove OS containment on a real systemd host; proves refusal
    # before execution in this unprivileged environment.
    marker=tmp_path/'NEVER'
    command=escaped_script.replace('"NEVER"',repr(str(marker)))
    with pytest.raises(ContainmentBlocked):
        CgroupV2Executor(tmp_path).run([sys.executable,'-c',command],timeout=1)
    assert not marker.exists()
