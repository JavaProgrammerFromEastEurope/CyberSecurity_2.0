"""Execute three complete strict cumulative tests, retaining all outcomes.

No Ubuntu opt-in, no external scanner CLI, no background/orphan tests outside
Python fixtures. Run this from any cwd after installing dev dependencies.
"""
from __future__ import annotations
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import time

ROOT=Path(__file__).resolve().parent.parent
OUT=ROOT/'evidence'/'stage65'
OUT.mkdir(parents=True,exist_ok=True)


def digest(value:bytes): return hashlib.sha256(value).hexdigest()


def run(label,cmd,*,timeout=180,env=None):
    started=time.monotonic()
    timed_out=False
    try:
        completed=subprocess.run(cmd,cwd=ROOT,env=env,capture_output=True,timeout=timeout,check=False)
        stdout,stderr,code=completed.stdout,completed.stderr,completed.returncode
    except subprocess.TimeoutExpired as exc:
        timed_out=True
        stdout,stderr,code=exc.stdout or b'',exc.stderr or b'',124
    (OUT/(label+'.stdout.log')).write_bytes(stdout)
    (OUT/(label+'.stderr.log')).write_bytes(stderr)
    (OUT/(label+'.exitcode')).write_text(str(code)+'\n',encoding='ascii')
    record={'name':label,'command':cmd,'exit_code':code,'seconds':round(time.monotonic()-started,3),
        'timed_out':timed_out,'status':'PASS' if code==0 and not timed_out else 'FAIL/TIMEOUT' if timed_out else 'FAIL',
        'stdout_sha256':digest(stdout),'stderr_sha256':digest(stderr),
        'stdout_tail':stdout.decode('utf-8','replace').splitlines()[-8:],
        'stderr_tail':stderr.decode('utf-8','replace').splitlines()[-8:]}
    return record


def main():
    env=os.environ.copy()
    env['PYTHONPATH']=str(ROOT/'src')
    env['PYTHONWARNINGS']='error::ResourceWarning,error::DeprecationWarning'
    for k in list(env):
        if k.startswith('CYBERSEC_UBUNTU_2610_') or k.startswith('CYBERSEC_STAGE65_') or k in (
            'CYBERSEC_EXECUTION_MODE','CYBERSEC_RUNTIME_MODE'):
            env.pop(k,None)
    scan_executables=('zap.sh','zaproxy','nuclei','sqlmap')
    presence={name:shutil.which(name,path=env.get('PATH','')) for name in scan_executables}
    (OUT/'external_scanner_inventory.json').write_text(json.dumps({
        'executables':presence,'external_scanner_invocations':0,
        'note':'Full regression invokes Python test suite only; external executables are not called'},indent=2)+'\n')
    if any(presence.values()):
        print('REFUSED: scanner executable in PATH; tests must not launch external scanners')
        return 3
    records=[]
    for n in range(1,4):
        label=f'final_full_strict_{n}'
        cmd=[sys.executable,'-W','error::ResourceWarning','-W','error::DeprecationWarning',
             '-m','pytest','-q','-ra','--tb=short','tests']
        record=run(label,cmd,timeout=240,env=env)
        records.append(record)
        (OUT/'final_regressions.json').write_text(json.dumps(records,indent=2,ensure_ascii=False)+'\n')
        print(json.dumps({k:v for k,v in record.items() if k not in ('stdout_tail','stderr_tail')},ensure_ascii=False),flush=True)
    return 0 if all(row['status']=='PASS' for row in records) else 1

if __name__=='__main__': sys.exit(main())
