#!/usr/bin/env python3
"""Fail-closed Stage70 V75 compose baseline reconciliation in a verified COPY.

The pinned Ubuntu R4 diagnostic proved the BASE Compose JSON already has a
zap.pids_limit (integer). The R5 change merely permits comparing a baseline
PID limit to a deliberately chosen bounded test value; all other fields must
remain identical after ignoring *exactly* those two allowed ZAP fields.
Original immutable R4 / R3 / V75 archives are never altered.
"""
from __future__ import annotations
import hashlib, json, re
from pathlib import Path

PINNED_R3_AUTORUNNER = '6d49bbe0d95d711b433e88807f8c716c27d7c8d2b1c4c501ab7fcb613df8777c'
PINNED_R3_PID_SOURCE = 'c00512ed73b409db5373c4a54dd96b8d58e7250c442f0ee37191e687b88023b6'
PINNED_V75_TEST_SOURCE = '9455ad11306e118ea1e3810edae5672188ddaeaa7bc0e5414394e37597959697'

def sha(data:bytes)->str:return hashlib.sha256(data).hexdigest()

PID_OLD='''    normalized=json.loads(json.dumps(after))
    normalized['services']['zap'].pop('pids_limit',None)
    normalized['services']['zap'].pop('shm_size',None)
    original=json.loads(json.dumps(before))
    require('pids_limit' not in original['services']['zap'], 'BASE_PID_BUDGET_UNEXPECTED')
    original['services']['zap'].pop('shm_size',None)
    require(normalized==original,'COMPOSE_UNAPPROVED_CHANGE')
    require('shm_size' not in before['services']['zap'],'BASE_SHM_UNEXPECTED')
'''
PID_NEW='''    # The pinned base lab Compose already has an integer pids_limit on ZAP.
    # Reject malformed, unlimited, bool, or unreasonably large base limits.
    # A *verified* pre-existing finite ZAP budget is not an unapproved change.
    base_zap=before['services']['zap']
    require(type(base_zap) is dict, 'COMPOSE_BASE_ZAP_INVALID')
    require('shm_size' not in base_zap, 'BASE_SHM_UNEXPECTED')
    if 'pids_limit' in base_zap:
        baseline=base_zap['pids_limit']
        if type(baseline) is str:
            require(re.fullmatch(r'[1-9][0-9]{0,6}',baseline) is not None,
                    'BASE_PID_LIMIT_NOT_CANONICAL')
            baseline=int(baseline)
        require(type(baseline) is int and 1<=baseline<=10000000,
                'BASE_PID_LIMIT_NOT_FINITE')
    # Complete structural equality enforces images, networks, UID, caps,
    # privileged, seccomp, no-new-privileges, mounts and all other fields.
    normalized=json.loads(json.dumps(after))
    normalized['services']['zap'].pop('pids_limit',None)
    normalized['services']['zap'].pop('shm_size',None)
    original=json.loads(json.dumps(before))
    original['services']['zap'].pop('pids_limit',None)
    original['services']['zap'].pop('shm_size',None)
    require(normalized==original,'COMPOSE_UNAPPROVED_CHANGE')
'''
TEST_OLD=''' def test_preexisting_compose_pids_limit_rejected(self):
  b=base_compose();b['services']['zap']['pids_limit']=80
  with self.assertRaises(p.BudgetBlocked):p.compose_pid_delta(b,changed(128),128)
'''
TEST_NEW=''' def test_preexisting_compose_finite_pids_limit_accepted(self):
  b=base_compose();b['services']['zap']['pids_limit']=80
  self.assertEqual(p.compose_pid_delta(b,changed(128),128)['pids_limit'],128)
 def test_preexisting_negative_pids_limit_rejected(self):
  b=base_compose();b['services']['zap']['pids_limit']=-1
  with self.assertRaises(p.BudgetBlocked):p.compose_pid_delta(b,changed(128),128)
 def test_preexisting_boolean_pids_limit_rejected(self):
  b=base_compose();b['services']['zap']['pids_limit']=True
  with self.assertRaises(p.BudgetBlocked):p.compose_pid_delta(b,changed(128),128)
 def test_preexisting_noncanonical_pids_limit_rejected(self):
  b=base_compose();b['services']['zap']['pids_limit']='00080'
  with self.assertRaises(p.BudgetBlocked):p.compose_pid_delta(b,changed(128),128)
'''

# Patch R3 launcher only *inside a verified extracted temporary copy*.
IMPORT='from root_fix_r3 import apply as apply_structural_root_fix\n'
IMPORT_NEW=IMPORT+'from r5_compose_fix import apply_compose_source_fix\n'
RUNNER_OLD='''            r3_proof=apply_structural_root_fix(project,record)
            report['r3_root_policy']=r3_proof
'''
RUNNER_NEW='''            r3_proof=apply_structural_root_fix(project,record)
            report['r3_root_policy']=r3_proof
            _progress(record,'R5_COMPOSE_POLICY','PATCHING_TEMPORARY_COPY',
                      'Pinned R4/R3/V75 unchanged; preserve all Compose fields except exact ZAP PID/shm')
            report['r5_compose_policy']=apply_compose_source_fix(project,record)
            _progress(record,'R5_COMPOSE_POLICY','PATCHED_VERIFIED',
                      'Existing baseline finite PID accepted; all unrelated deltas remain BLOCKED')
'''

def replace_pinned(raw,expected,old,new,name):
    if sha(raw)!=expected:raise ValueError(name+'_ORIGINAL_SHA256_MISMATCH')
    code=raw.decode('utf-8','strict')
    if code.count(old)!=1:raise ValueError(name+'_PATCH_ANCHOR_MISMATCH')
    out=code.replace(old,new).encode('utf-8')
    compile(out, name, 'exec')
    return out

def patch_r3_autorunner(script:Path)->dict:
    original=Path(script).read_bytes()
    if sha(original)!=PINNED_R3_AUTORUNNER:raise ValueError('R3_AUTORUNNER_ORIGINAL_SHA_MISMATCH')
    code=original.decode('utf-8','strict')
    if code.count(IMPORT)!=1 or code.count(RUNNER_OLD)!=1:
        raise ValueError('R3_AUTORUNNER_PATCH_ANCHOR_INVALID')
    revised=code.replace(IMPORT, IMPORT_NEW).replace(RUNNER_OLD, RUNNER_NEW).encode('utf-8')
    compile(revised,'auto_runner.py','exec')
    Path(script).write_bytes(revised)
    return {'original_sha256':sha(original),'patched_sha256':sha(revised)}

def apply_compose_source_fix(project:Path,record:Path|None=None)->dict:
    """Called AFTER original R3 root patch updates SOURCE_SHA256.json."""
    project=Path(project)
    manifest_path=project/'SOURCE_SHA256.json'
    manifest=json.loads(manifest_path.read_text('utf-8'))
    pid=project/'pid_recovery.py'
    test=project/'tests/test_v75_pid_recovery.py'
    orig_pid=pid.read_bytes(); orig_test=test.read_bytes()
    if manifest.get('files',{}).get('pid_recovery.py')!=sha(orig_pid):
        raise ValueError('R3_PID_MANIFEST_MISMATCH')
    if manifest['files'].get('tests/test_v75_pid_recovery.py')!=PINNED_V75_TEST_SOURCE:
        raise ValueError('V75_TEST_MANIFEST_MISMATCH')
    # Require the *exact* R3-transformed PID source, never arbitrary code.
    if sha(orig_pid)!=PINNED_R3_PID_SOURCE:
        raise ValueError('R3_PID_PRE_PATCH_SHA256_MISMATCH')
    new_pid=replace_once(orig_pid,PID_OLD,PID_NEW,'PID_DELTA')
    new_test=replace_pinned(orig_test,PINNED_V75_TEST_SOURCE,TEST_OLD,TEST_NEW,'test_v75_pid_recovery.py')
    # Update source hashes only after both patches have been proven applicable.
    pid.write_bytes(new_pid)
    test.write_bytes(new_test)
    sums=project/'SHA256SUMS.txt'
    oldlines=sums.read_text('ascii').splitlines()
    keys={line.split('  ',1)[1] for line in oldlines if '  ' in line}
    if len(keys)!=len(oldlines) or set(manifest['files'])!=(keys|{'SHA256SUMS.txt'}):
        raise ValueError('R3_HASH_LEDGER_FILESET_INVALID')
    if any((project/x).is_symlink() or not (project/x).is_file() or '..' in Path(x).parts for x in keys):
        raise ValueError('R3_FILESET_UNSAFE')
    newlines=[sha((project/x).read_bytes())+'  '+x for x in (line.split('  ',1)[1] for line in oldlines)]
    sums.write_text('\n'.join(newlines)+'\n','ascii')
    for key in list(manifest['files']):
        manifest['files'][key]=sha((project/key).read_bytes())
    manifest_path.write_text(json.dumps(manifest,sort_keys=True,ensure_ascii=True,indent=2)+'\n','utf-8')
    verify=json.loads(manifest_path.read_text('utf-8'))
    if any(sha((project/k).read_bytes())!=v for k,v in verify['files'].items()):
        raise ValueError('R5_MANIFEST_RECHECK_FAILED')
    report={'schema':'stage70-v75-compose-baseline-pid-fix-r5',
            'base_v75_source':'PINNED_AND_UNMODIFIED','r3_root_fix':'APPLIED_PRIOR',
            'previous_pid_sha256':sha(orig_pid),'patched_pid_sha256':sha(new_pid),
            'test_sha256':sha(new_test),'source_manifest_sha256':sha(manifest_path.read_bytes()),
            'scope':'ONLY_ZAP_PID_LIMIT_AND_256M_SHM','unrelated_changes':'BLOCKED',
            'production':'BLOCKED/NO-GO','day04':'NOT_RUN','stage71':'NOT_OPENED'}
    if record:(Path(record)/'R5_COMPOSE_POLICY.json').write_text(json.dumps(report,indent=2,sort_keys=True)+'\n')
    return report

def replace_once(raw:bytes, old:str,new:str,label:str)->bytes:
    s=raw.decode('utf-8','strict')
    if s.count(old)!=1:raise ValueError(label+'_PATCH_ANCHOR_MISMATCH')
    out=s.replace(old,new).encode('utf-8')
    compile(out,label+'.py','exec')
    return out
