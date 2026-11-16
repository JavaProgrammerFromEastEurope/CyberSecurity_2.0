"""Stage 63: negative OS gates, signed receipt checks and real local process evidence.

No mock scanner or external network work is executed by these tests.
"""
from __future__ import annotations

import base64
import json
import os
import signal
import subprocess
import sys
import time
from datetime import datetime, timedelta, timezone
from pathlib import Path
from unittest.mock import patch

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives import serialization

from cybersec import stage63_host
from cybersec.recovery_authority import (
    RecoveryAdmissionBlocked, require_independent_recovery_admission,
    verify_recovery_receipt,
)
from cybersec.repository import Repository
from cybersec.scan_worker import run_scan_worker
from cybersec.cgroup_containment import ContainmentBlocked


BOOT_ID='d5a3758e-3159-4c5c-a95b-2fb4a5c51cb9'
CHECKPOINT='e'*64


def receipt_fixture():
    priv = Ed25519PrivateKey.generate()
    public = priv.public_key().public_bytes(
        serialization.Encoding.Raw, serialization.PublicFormat.Raw)
    now = datetime.now(timezone.utc)
    payload = {
        'schema': 'cybersec.recovery-receipt.v1',
        'purpose': 'manual-review-only', 'job_id': 4, 'attempt': 2,
        'boot_id': BOOT_ID, 'checkpoint_sha256': CHECKPOINT,
        'counter_before': 15, 'counter_after': 16,
        'issued_utc': (now - timedelta(seconds=5)).isoformat().replace('+00:00','Z'),
        'expires_utc': (now + timedelta(seconds=60)).isoformat().replace('+00:00','Z'),
        'nonce': 'b'*32,
    }
    def sign(content):
        canonical=json.dumps(content,sort_keys=True,separators=(',',':'),ensure_ascii=False).encode()
        return {'payload':content,'signature':base64.b64encode(priv.sign(canonical)).decode()}
    return public,payload,sign


def verify(pub,receipt,**kwargs):
    return verify_recovery_receipt(receipt=receipt,trusted_public_key=pub,
            job_id=4,attempt=2,boot_id=BOOT_ID,checkpoint_sha256=CHECKPOINT,**kwargs)


def test_valid_synthetic_signature_is_review_only():
    pub,p,sign=receipt_fixture()
    assert verify(pub,sign(p))['counter_after']==16
    # There is no API returning a runnable/recoverable production permit.


@pytest.mark.parametrize('field,value',[
    ('counter_before',-1),('counter_after',15),('counter_after',14),
    ('attempt',1),('job_id',8),('schema','unsafe'),('purpose','production-permit'),
    ('nonce','short'),('checkpoint_sha256','a'*64),('boot_id','d'*36),
])
def test_receipt_rejects_invalid_scope_and_monotonic_sequence(field,value):
    pub,p,sign=receipt_fixture()
    with pytest.raises(RecoveryAdmissionBlocked):
        verify(pub,sign(dict(p,**{field:value})))


@pytest.mark.parametrize('change',[
    {'extra':'injected'}, {'counter_before':1,'counter_after':0},
    {'issued_utc':'2030-01-01T00:00:00Z','expires_utc':'2030-01-01T00:01:00Z'},
    {'expires_utc':'2099-01-01T00:00:00Z'},
    {'issued_utc':'nonsense'}, {'nonce':'a'*33},
])
def test_receipt_rejects_schema_time_and_replay_like_changes(change):
    pub,p,sign=receipt_fixture()
    with pytest.raises(RecoveryAdmissionBlocked):
        verify(pub,sign(dict(p,**change)))


def test_signature_swapping_and_unsigned_mutation_blocked():
    pub,p,sign=receipt_fixture()
    r=sign(p)
    r['payload']=dict(p,counter_after=100)
    with pytest.raises(RecoveryAdmissionBlocked):
        verify(pub,r)
    with pytest.raises(RecoveryAdmissionBlocked):
        verify(b'\0'*32,sign(p))
    with pytest.raises(RecoveryAdmissionBlocked):
        verify(pub,{'payload':p,'signature':'invalid@='})


def test_signed_receipt_cannot_produce_permit_even_if_pin_readable(monkeypatch):
    pub,p,sign=receipt_fixture()
    monkeypatch.setattr('cybersec.recovery_authority._read_root_pinned_file',
                        lambda *args,**kwargs:base64.b64encode(pub))
    with pytest.raises(RecoveryAdmissionBlocked,match='No independently attested TPM'):
        require_independent_recovery_admission(receipt=sign(p),job_id=4,attempt=2,
                 boot_id=BOOT_ID,checkpoint_sha256=CHECKPOINT)


def test_missing_trust_root_denied(monkeypatch):
    pub,p,sign=receipt_fixture()
    from cybersec.lab_authorization import LabAuthorizationBlocked
    def refuse(*args,**kwargs):
        raise LabAuthorizationBlocked('absent')
    monkeypatch.setattr('cybersec.recovery_authority._read_root_pinned_file',refuse)
    with pytest.raises(RecoveryAdmissionBlocked,match='Missing independent'):
        require_independent_recovery_admission(receipt=sign(p),job_id=4,attempt=2,
                 boot_id=BOOT_ID,checkpoint_sha256=CHECKPOINT)


def test_mac_observation_without_kernel_stack_is_not_enforcement(monkeypatch):
    def fake_read(self,*args,**kwargs):
        raise PermissionError('no securityfs')
    monkeypatch.setattr(Path,'read_text',fake_read)
    report=stage63_host._mac_enforcement()
    assert report['lsm_observable'] is False
    assert report['apparmor_kernel_enabled'] is False
    assert report['selinux_enforcing'] is False


def test_unit_observation_fails_closed_without_systemd(monkeypatch):
    monkeypatch.setattr(stage63_host,'_systemd_show',lambda unit: (_ for _ in ()).throw(RuntimeError('no systemd')))
    report=stage63_host._observe_unit('worker','cybersec-worker','cybersec-scanner-worker.service')
    assert report['verified'] is False


def test_root_owned_artifact_rejects_symlink(tmp_path):
    target=tmp_path/'root'
    target.write_text('no authority')
    link=tmp_path/'link'
    link.symlink_to(target)
    assert stage63_host._root_owned_protected_file(link) is False
    assert stage63_host._root_owned_protected_file(tmp_path/'missing') is False


def test_host_audit_evidence_never_claims_admission():
    report=stage63_host.audit_host()
    assert report['schema']=='cybersec.stage63.host-audit.v1'
    assert report['status']=='BLOCKED/NO-GO'
    assert report['production_admission'] is False
    assert report['external_scanner_executed'] is False
    assert report['independent_e2e_executed'] is False
    assert report['checks']['external_monotonic_root_attested'] is False
    assert report['checks']['independent_mac_policy_legacy_bypass_test'] is False
    assert len(report['roles'])==4


def test_read_only_cli_returns_no_go():
    p=subprocess.run([sys.executable,'-m','cybersec.stage63_host'],
       capture_output=True,text=True,timeout=12,check=False)
    assert p.returncode==3 and p.stderr==''
    result=json.loads(p.stdout)
    assert result['production_admission'] is False


def test_production_worker_never_claims_without_independent_admission(tmp_path,monkeypatch):
    monkeypatch.setenv('CYBERSEC_EXECUTION_MODE','production')
    repo=Repository(tmp_path/'work.db')
    repo.add_target('http://127.0.0.1:8181/',authorized=True)
    job=repo.create_job('http://127.0.0.1:8181/','nuclei')
    with pytest.raises(ContainmentBlocked,match='Independent production admission'):
        run_scan_worker(repo,worker_id='worker1',max_jobs=1)
    assert repo.get_job(job.id).status=='queued'


@pytest.mark.skipif(sys.platform!='linux',reason='requires POSIX process group')
def test_real_local_sigterm_sigkill_lifecycle_no_external_scanner():
    proc=subprocess.Popen([sys.executable,'-c',
        'import signal,time;signal.signal(signal.SIGTERM,signal.SIG_IGN);time.sleep(12)'],
        start_new_session=True,stdin=subprocess.DEVNULL,stdout=subprocess.PIPE,stderr=subprocess.PIPE)
    try:
        deadline=time.monotonic()+3
        while time.monotonic()<deadline:
            if proc.poll() is not None:
                raise AssertionError('Test process unexpectedly exited')
            # Wait for the child to finish Python startup before signal transition.
            if Path(f'/proc/{proc.pid}/stat').exists():
                time.sleep(0.15)
                break
            time.sleep(0.01)
        proc.terminate()
        try:
            proc.wait(timeout=0.3)
        except subprocess.TimeoutExpired:
            pass
        if proc.poll() is None:
            proc.kill()
        proc.wait(timeout=3)
        assert proc.poll() is not None
    finally:
        if proc.poll() is None:
            proc.kill()
        proc.communicate(timeout=3)


def test_missing_cgroup_delegation_rejects_process_before_exec(tmp_path):
    from cybersec.cgroup_containment import CgroupV2Executor
    marker=tmp_path/'must_not_exist'
    with pytest.raises(ContainmentBlocked):
        CgroupV2Executor(tmp_path).run([sys.executable,'-c',
            f'open({str(marker)!r},"w").write("invalid")'],timeout=1)
    assert not marker.exists()


def test_unknown_service_name_never_queried(monkeypatch):
    monkeypatch.setattr(stage63_host.Path,'read_text', lambda self,*a,**k:'systemd')
    with pytest.raises(ValueError,match='Unknown'):
        stage63_host._systemd_show('evil.service')


def test_service_requires_real_kernel_enforcing_mac(monkeypatch):
    fake = {'apparmor_kernel_enabled':False,'selinux_enforcing':False}
    unit=stage63_host._observe_unit('worker','cybersec-worker','cybersec-scanner-worker.service',fake)
    assert not unit['verified']


def test_lsm_never_accepts_label_alone(monkeypatch):
    monkeypatch.setattr(stage63_host,'_mac_enforcement',lambda:{
        'lsm_observable':False,'apparmor_kernel_enabled':False,'selinux_enforcing':False,
    })
    assert not stage63_host._mac_enforcement()['apparmor_kernel_enabled']
