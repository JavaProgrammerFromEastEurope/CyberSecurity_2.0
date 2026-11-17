"""Pure Python stage65 contracts: absolutely no external scanner execution."""
import json
import os
from pathlib import Path
import sqlite3
from contextlib import closing
from concurrent.futures import ThreadPoolExecutor
import threading
import time

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from cybersec.stage65.contracts import Permit, PermitError, PermitVerifier, argv_digest, sign_permit
from cybersec.stage65.ledger import WitnessLedger, InMemoryAnchor, LedgerBlocked, WitnessHead
from cybersec.stage65.witness import WitnessStore, _head
from cybersec.stage65.host import RoleMap, HostAdmission
from cybersec.stage65.broker import AdmissionBroker


@pytest.fixture
def signed():
    key=Ed25519PrivateKey.generate()
    verifier=PermitVerifier(key.public_key(),issuer='trusted-attester')
    clock=int(time.time())
    args=('/bin/echo','fixture')
    permit=Permit('cybersec.stage65.permit.v1','permit-65-01','attempt-65-01',
                  argv_digest(args),1001,'lab/fixture',clock-1,clock+80,
                  'trusted-attester',1)
    return key,verifier,permit,args,clock


def verify(signed,token,**kw):
    _,v,p,args,clock=signed
    req=dict(attempt_id=p.attempt_id,args=args,worker_uid=p.worker_uid,
             scope=p.scope,generation=p.generation,now=clock)
    req.update(kw)
    return v.verify(token,**req)


def test_signed_context_happy(signed):
    key,_,p,_,_=signed
    assert verify(signed,sign_permit(p,key)) == p


@pytest.mark.parametrize('change',[
    {'attempt_id':'other'},{'args':['/bin/echo','not-fixture']},
    {'worker_uid':1002},{'scope':'lab/wrong'},{'generation':2},
    {'now':1},{'now':9999999999}])
def test_permit_rejects_context_replay(signed,change):
    key,_,p,_,_=signed
    with pytest.raises(PermitError): verify(signed,sign_permit(p,key),**change)


def test_signature_tamper_wrong_attester_and_duplicate_json(signed):
    key,v,p,_,_=signed
    token=sign_permit(p,key)
    d=json.loads(token)
    d['payload']['worker_uid']=1234
    with pytest.raises(PermitError): verify(signed,json.dumps(d))
    other=Ed25519PrivateKey.generate()
    with pytest.raises(PermitError): verify(signed,sign_permit(p,other))
    with pytest.raises(PermitError): verify(signed,token.replace('"payload":{','"payload":{},"payload":{',1))


@pytest.mark.parametrize('bad',[
    {'schema':'wrong'}, {'permit_id':'../path'}, {'attempt_id':'bad x'},
    {'worker_uid':0}, {'worker_uid':True}, {'generation':0},
    {'expires_at':9999999999}, {'scope':'foo/../bar'}, {'argv_sha256':'bad'},
])
def test_invalid_permit_never_signed(signed,bad):
    key,_,p,_,_=signed
    from dataclasses import replace
    with pytest.raises(PermitError): sign_permit(replace(p,**bad),key)


def test_single_use_persists_restart(signed,tmp_path):
    _,_,p,_,_=signed
    anchor=InMemoryAnchor()
    db=tmp_path/'ledger.sqlite3'
    head=WitnessLedger(db,anchor).consume(p)
    assert head.seq==1 and head==anchor.read()
    recreated=WitnessLedger(db,anchor)
    assert recreated.recover()==head
    assert recreated.status(p.permit_id)=='used'
    with pytest.raises(LedgerBlocked): recreated.consume(p)


def test_attempt_reuse_with_new_permit_id_denied(signed,tmp_path):
    from dataclasses import replace
    _,_,p,_,_=signed
    ledger=WitnessLedger(tmp_path/'ledger.db',InMemoryAnchor())
    ledger.consume(p)
    with pytest.raises(LedgerBlocked): ledger.consume(replace(p,permit_id='permit-65-02'))


def test_pending_without_witness_cas_abandoned(signed,tmp_path):
    _,_,p,_,_=signed
    anchor=InMemoryAnchor()
    ledger=WitnessLedger(tmp_path/'ledger.db',anchor)
    def refuse(prior,proposal): return False
    anchor.compare_and_swap=refuse
    with pytest.raises(LedgerBlocked):ledger.consume(p)
    assert ledger.status(p.permit_id)=='pending'
    ledger.recover()
    assert ledger.status(p.permit_id)=='aborted'
    with pytest.raises(LedgerBlocked):ledger.consume(p)


def test_crash_after_cas_recovers_used(signed,tmp_path,monkeypatch):
    _,_,p,_,_=signed
    anchor=InMemoryAnchor()
    ledger=WitnessLedger(tmp_path/'ledger.db',anchor)
    original=ledger.recover
    calls=0
    def crash():
        nonlocal calls
        calls+=1
        if calls==2: raise SystemExit('SIGKILL-like injection after external CAS')
        return original()
    monkeypatch.setattr(ledger,'recover',crash)
    with pytest.raises(SystemExit): ledger.consume(p)
    assert anchor.read().seq == 1
    recovered=WitnessLedger(tmp_path/'ledger.db',anchor)
    assert recovered.recover()==anchor.read()
    assert recovered.status(p.permit_id)=='used'


def test_rollback_of_sqlite_detected(signed,tmp_path):
    from dataclasses import replace
    _,_,p,_,_=signed
    anchor=InMemoryAnchor()
    older=tmp_path/'before.db'
    live=tmp_path/'ledger.db'
    ledger=WitnessLedger(live,anchor)
    # sqlite backup creates consistent pre-consumption base image.
    with closing(sqlite3.connect(live)) as src, closing(sqlite3.connect(older)) as dst: src.backup(dst)
    ledger.consume(p)
    with closing(sqlite3.connect(older)) as src, closing(sqlite3.connect(live)) as dst: src.backup(dst)
    with pytest.raises(LedgerBlocked,match='rollback|divergence'):
        WitnessLedger(live,anchor).recover()


def test_concurrent_claim_serializes_and_never_double_dispatch(signed,tmp_path):
    _,_,p,_,_=signed
    anchor=InMemoryAnchor()
    db=tmp_path/'ledger.db'
    ledger=WitnessLedger(db,anchor)
    barrier=threading.Barrier(4)
    def claim(_):
        barrier.wait(timeout=4)
        try:
            ledger.consume(p)
            return 'PASS'
        except LedgerBlocked:
            return 'BLOCKED'
    with ThreadPoolExecutor(max_workers=4) as pool:
        results=list(pool.map(claim,range(4)))
    assert results.count('PASS')<=1
    assert results.count('PASS')+results.count('BLOCKED')==4
    assert anchor.read().seq<=1


def test_cross_uid_and_missing_host_evidence_refuse_before_consumption(signed,tmp_path):
    key,ver,p,args,now=signed
    anchor=InMemoryAnchor()
    ledger=WitnessLedger(tmp_path/'ledger.db',anchor)
    roles=RoleMap(broker=1000,worker=1001,attester=1002,witness=1003,publisher=1004)
    class CannotRun:
        def recover_orphans(self): raise AssertionError('not called')
        def run(self,*a,**kw): raise AssertionError('not called')
    host=HostAdmission(expected_profile='cybersec-broker',fixed_cgroup=Path('/unavailable'),
                       installed_unit=Path('/unavailable'),approved_policy_digest='0'*64)
    broker=AdmissionBroker(roles=roles,host=host,verifier=ver,ledger=ledger,
                           kernel=CannotRun(),executable_allowlist={'fixture':args})
    token=sign_permit(p,key)
    req=dict(command='fixture',token=token,attempt_id=p.attempt_id,
             permit_scope=p.scope,generation=p.generation)
    with pytest.raises(LedgerBlocked,match='kernel|credentials'):
        broker.admit_and_run(caller_uid=1003,**req)
    with pytest.raises(LedgerBlocked): broker.admit_and_run(caller_uid=1001,**req)
    assert ledger.status(p.permit_id) is None
    assert anchor.read().seq==0


def test_all_uids_must_be_unique():
    with pytest.raises(LedgerBlocked):
        RoleMap(broker=1000,worker=1000,attester=1002,witness=1003,publisher=1004).verify()


def test_witness_cas_is_durable_across_store_instances(tmp_path):
    db=tmp_path/'witness.db'
    a=WitnessStore(db)
    prior=a.read()
    proposed=WitnessHead(1,'a'*64)
    assert a.compare_and_swap(prior,proposed)
    assert not WitnessStore(db).compare_and_swap(prior,WitnessHead(1,'b'*64))
    assert WitnessStore(db).read()==proposed


def test_invalid_witness_head():
    for bad in ({'seq':True,'digest':'0'*64},{'seq':0,'digest':'../'},
                {'seq':-1,'digest':'0'*64}):
        with pytest.raises(LedgerBlocked): _head(bad)


def test_production_gate_still_refuses(monkeypatch):
    from cybersec.production_admission import require_production_admission
    monkeypatch.setenv('CYBERSEC_EXECUTION_MODE','production')
    with pytest.raises(PermissionError,match='BLOCKED/NO-GO'):
        require_production_admission(action='scanner')


def _kill_claim_process(database, rootdb, permit, phase):
    """A real SIGKILL at a deterministic SQLite/witness boundary."""
    import signal
    from cybersec.stage65.witness import WitnessStore
    from cybersec.stage65.ledger import WitnessLedger
    class CrashAnchor(WitnessStore):
        def compare_and_swap(self,prior,proposed):
            if phase=='pre_cas': os.kill(os.getpid(),signal.SIGKILL)
            accepted=super().compare_and_swap(prior,proposed)
            if phase=='post_cas': os.kill(os.getpid(),signal.SIGKILL)
            return accepted
    ledger=WitnessLedger(Path(database),CrashAnchor(Path(rootdb)))
    ledger.consume(permit)
    if phase=='post_commit': os.kill(os.getpid(),signal.SIGKILL)


@pytest.mark.parametrize('phase,expected_seq,expected_status',[
    ('pre_cas',0,'aborted'),('post_cas',1,'used'),('post_commit',1,'used')])
def test_real_sigkill_sqlite_witness_recovery(signed,tmp_path,phase,expected_seq,expected_status):
    import multiprocessing
    import signal
    _,_,permit,_,_=signed
    path=tmp_path/'ledger.db'
    rootdb=tmp_path/'external-witness.db'
    # Root is in a different file; crash consistency, not hostile rollback proof.
    WitnessStore(rootdb)
    process=multiprocessing.Process(target=_kill_claim_process,
                                    args=(str(path),str(rootdb),permit,phase))
    process.start()
    try:
        process.join(6)
        assert process.exitcode == -signal.SIGKILL
    finally:
        if process.is_alive(): process.kill(); process.join(3)
    root=WitnessStore(rootdb)
    assert root.read().seq==expected_seq
    ledger=WitnessLedger(path,root)
    ledger.recover()
    assert ledger.status(permit.permit_id)==expected_status
    with pytest.raises(LedgerBlocked): ledger.consume(permit)


def test_bad_witness_socket_is_rejected(tmp_path):
    from cybersec.stage65.witness import SocketWitnessAnchor
    target=tmp_path/'target'
    target.write_text('fake')
    link=tmp_path/'witness.sock'
    link.symlink_to(target)
    anchor=SocketWitnessAnchor(link,expected_witness_uid=1222)
    with pytest.raises(LedgerBlocked,match='symlink'):
        anchor.read()


def test_host65_cli_blocks_even_with_readable_inventory(capsys):
    from cybersec.stage65.preflight import main
    assert main([])==3
    body=json.loads(capsys.readouterr().out)
    assert body['status']=='BLOCKED/NO-GO'
    assert body['production_admitted'] is False
    assert body['checks']['kernel_app_armor_negative_tests'] is False
