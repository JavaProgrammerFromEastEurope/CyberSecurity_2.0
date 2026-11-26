#!/usr/bin/env python3
"""Restore original V74 byte-for-byte; delegate historical commands safely."""
import sys
sys.dont_write_bytecode=True
from pathlib import Path
import hashlib,lzma,zipfile,io,tempfile,subprocess,os
ROOT=Path(__file__).resolve().parent
NAME='Stage70_ZAP_API_AJAX_SPIDER_PASSIVE_FOCUSED_V74_CROSS_PHASE_PID_DENIAL_FIREFOX_EXIT_ATTRIBUTION_LT10MB'
EXPECTED='8c4108e3af996e053188c5da55d04454c1891f876e333f8d9910a52d49ecf9a0'
SIZE=9188012
COUNT=109

def checked():
 raw=lzma.decompress((ROOT/'HISTORY/ORIGINAL_V74_UNCHANGED.zip.xz').read_bytes(),memlimit=128*1024*1024)
 if len(raw)!=SIZE or hashlib.sha256(raw).hexdigest()!=EXPECTED:raise ValueError('V74_ORIGINAL_SHA_INVALID')
 with zipfile.ZipFile(io.BytesIO(raw)) as z:
  if z.testzip() is not None or len(z.namelist())!=COUNT:raise ValueError('V74_ORIGINAL_CRC_INVALID')
 return raw

def inherited(script,args=()):
 allowed={f'restore_v{i}.py' for i in range(65,74)}|{'audit_lineage.py','audit_evidence.py',
 'audit_evidence_v68.py','audit_evidence_v69.py','audit_evidence_v70.py','audit_evidence_v71.py',
 'audit_evidence_v72.py','audit_evidence_v73.py','integrity_selftest.py'}
 if script not in allowed:raise ValueError('INHERITED_SCRIPT_FORBIDDEN')
 with tempfile.TemporaryDirectory(prefix='v75_immutable_v74_') as td:
  with zipfile.ZipFile(io.BytesIO(checked())) as z:
   for info in z.infolist():
    p=Path(info.filename)
    if p.is_absolute() or '..' in p.parts:raise ValueError('V74_ZIP_TRAVERSAL')
   z.extractall(td)
  p=subprocess.run([sys.executable,'-B',script,*args],cwd=Path(td)/NAME,
   env={**os.environ,'PYTHONDONTWRITEBYTECODE':'1',
        'PYTHONWARNINGS':'error::ResourceWarning,error::DeprecationWarning'},
   capture_output=True,timeout=240)
  sys.stdout.buffer.write(p.stdout);sys.stderr.buffer.write(p.stderr)
  if p.returncode:raise SystemExit(p.returncode)

if __name__=='__main__':
 if sys.argv!=[sys.argv[0],'verify']:raise SystemExit(4)
 checked();print('V74_ORIGINAL_BYTE_EXACT_PASS')
