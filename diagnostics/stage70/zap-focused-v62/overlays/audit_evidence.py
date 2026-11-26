#!/usr/bin/env python3
"""Provenance/CRC integrity and V61 17:55 UTC conclusion from supplied EVIDENCE."""
from pathlib import Path
from zipfile import ZipFile
import hashlib,io,json
root=Path(__file__).resolve().parent
sha=lambda b:hashlib.sha256(b).hexdigest()
p=root/'EVIDENCE/ORIGINAL_USER_EVIDENCE_V61_UNCHANGED.zip'
b=p.read_bytes()
assert sha(b)==(p.with_suffix(p.suffix+'.sha256')).read_text().split()[0]
with ZipFile(io.BytesIO(b)) as outer:
    assert outer.testzip() is None
    names=outer.namelist()
    assert all(not Path(n).is_absolute() and '..' not in Path(n).parts for n in names)
    path='EVIDENCE/ZAP_FOCUSED_MAC_V61_20261125T175500Z/VM_ZAP_FOCUSED_EVIDENCE.zip'
    nested=outer.read(path)
    exp=outer.read(path+'.sha256').decode().split()[0]
    assert sha(nested)==exp
    for n in ('EVIDENCE/ZAP_FOCUSED_MAC_V61_20261125T175500Z/MAC_FOCUSED_STATUS.json',):
        status=json.loads(outer.read(n))
        assert status['vm_exit_code']==4 and status['production']=='BLOCKED/NO-GO'
with ZipFile(io.BytesIO(nested)) as zz:
    assert zz.testzip() is None
    n=next(x for x in zz.namelist() if x.endswith('/ZAP_FOCUSED_STATUS.json'))
    state=json.loads(zz.read(n))
    trace=state['api_trace']
    assert state['checks']['api_ready']=='PASS' and state['checks']['api_readiness_diagnostic']['api_error_count']==10
    assert state['checks']['targeted_tests']=='PASS_NO_SKIPS_OR_WARNINGS'
    assert state['spider']=='NOT_RUN' and state['passive']=='NOT_RUN' and state['ajax_spider']=='NOT_RUN'
    assert trace[-1]['operation']=='context.action.includeInContext' and trace[-1]['result']=='PASS'
    assert state['error'].startswith('TimeoutExpired: Command')
    assert not state['checks'].get('direct_marionette_about_blank_control')
    assert state['overall']=='BLOCKED/NO-GO'
print(json.dumps({'schema':'stage70-v62-inherited-evidence-audit-v1',
 'user_evidence_sha256':sha(b),'user_evidence_crc':'PASS',
 'v61_vm_evidence_sha256':sha(nested),'v61_vm_evidence_crc':'PASS',
 'v61_api':'PASS_AFTER_10_RETRIES', 'v61_last_confirmed_api':'context.action.includeInContext',
 'v61_failure':'DOCKER_EXEC_TIMEOUT_AFTER_CONTEXT_INCLUDE',
 'v61_native_marionette':'NOT_REACHED',
 'v61_spider':'NOT_RUN','v61_ajax':'NOT_RUN','v61_passive':'NOT_RUN',
 'production':'BLOCKED/NO-GO','stage71':'NOT_OPENED'},sort_keys=True,indent=2))
