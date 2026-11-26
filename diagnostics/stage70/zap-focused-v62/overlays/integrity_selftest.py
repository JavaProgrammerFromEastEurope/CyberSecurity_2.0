#!/usr/bin/env python3
"""Negative tests of read-only V62 source-integrity verifier; no original edits."""
from pathlib import Path
import tempfile,shutil,importlib.util,json,contextlib,io
r=Path(__file__).resolve().parent
spec=importlib.util.spec_from_file_location('v62_mac_negative',r/'mac_run.py')
m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m)
scenarios=[
 ('tamper_vm_source','zap_focus_vm.py','alter'),
 ('tamper_mac_runner','mac_run.py','alter'),
 ('tamper_readme','README_RU.md','alter'),
 ('tamper_v61_predecessor','HISTORY/ORIGINAL_V61_UNCHANGED.zip.xz','alter'),
 ('tamper_v61_sha','HISTORY/ORIGINAL_V61_SHA256.txt','alter'),
 ('tamper_evidence','EVIDENCE/ORIGINAL_USER_EVIDENCE_V61_UNCHANGED.zip','alter'),
 ('tamper_evidence_sha','EVIDENCE/ORIGINAL_USER_EVIDENCE_V61_UNCHANGED.zip.sha256','alter'),
 ('tamper_fixture_tests','tests/test_v62_preflight_timeout.py','alter'),
 ('tamper_audit','audit_evidence.py','alter'),
 ('remove_source','zap_focus_vm.py','remove'),
 ('symlink_source','zap_focus_vm.py','symlink'),
 ('add_unlisted','ZAP_EXTRA_FILE.txt','add'),
]
rows=[]
orig=m.ROOT
for label,relative,kind in scenarios:
    with tempfile.TemporaryDirectory(prefix='v62_negative_') as d:
        root=Path(d)/'copy'
        shutil.copytree(r,root,symlinks=True)
        p=root/relative
        if kind=='alter':
            with p.open('ab') as f:f.write(b'CORRUPTED_MARKER')
        elif kind in ('remove','symlink'):
            p.unlink()
            if kind=='symlink':p.symlink_to('/nonexistent/sensitive-outside-target')
        elif kind=='add':p.write_text('unlisted')
        m.ROOT=root
        try:
            with contextlib.redirect_stdout(io.StringIO()):m.verify()
        except (RuntimeError,ValueError,OSError,KeyError) as exc:
            rows.append({'name':label,'expected':'REJECT','actual':'REJECT',
                         'error_type':type(exc).__name__})
        else:
            rows.append({'name':label,'expected':'REJECT','actual':'INVALID_ACCEPT'})
m.ROOT=orig
assert len(rows)==len(scenarios) and all(x['actual']=='REJECT' for x in rows)
print(json.dumps({'schema':'stage70-v62-integrity-negatives-v1',
 'passed':len(rows),'failed':0,'results':rows},indent=2,sort_keys=True))
