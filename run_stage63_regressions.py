"""Record strict regression evidence as independent invocations; preserve FAILs."""
from __future__ import annotations
import hashlib
import json
import os
import subprocess
import sys
import time
from datetime import datetime, timezone
from pathlib import Path

root=Path(__file__).resolve().parent
folder=root/'evidence/stage63'
folder.mkdir(parents=True,exist_ok=True)


def run(name: str, cmd: list[str], *, timeout: int = 160) -> dict:
    start=datetime.now(timezone.utc)
    env={**os.environ,'PYTHONPATH':str(root/'src'),'PYTHONDONTWRITEBYTECODE':'1'}
    begun=time.monotonic()
    timed_out=False
    try:
        cp=subprocess.run(cmd,cwd=root,env=env,capture_output=True,timeout=timeout,check=False)
        out,err,code=cp.stdout,cp.stderr,cp.returncode
    except subprocess.TimeoutExpired as exc:
        timed_out=True;out=exc.stdout or b'';err=(exc.stderr or b'')+b'\nCOMMAND TIMEOUT\n';code=124
    elapsed=round(time.monotonic()-begun,3)
    base=folder/name
    stdout=base.with_suffix('.stdout');stderr=base.with_suffix('.stderr')
    stdout.write_bytes(out);stderr.write_bytes(err)
    result={'name':name,'command':cmd,'started_at_utc':start.isoformat(),'elapsed_seconds':elapsed,
            'exit_code':code,'timed_out':timed_out,
            'stdout_sha256':hashlib.sha256(out).hexdigest(),'stderr_sha256':hashlib.sha256(err).hexdigest(),
            'stdout_bytes':len(out),'stderr_bytes':len(err)}
    base.with_suffix('.json').write_text(json.dumps(result,sort_keys=True,indent=2)+'\n')
    print(json.dumps(result),flush=True)
    return result


if __name__=='__main__':
    if len(sys.argv)!=2 or sys.argv[1] not in ('full1','full2','full3','focused','audit'):
        raise SystemExit('usage: python run_stage63_regressions.py full1|full2|full3|focused|audit')
    arg=sys.argv[1]
    flags=['-W','error::ResourceWarning','-W','error::DeprecationWarning',
           '-W','error::pytest.PytestUnraisableExceptionWarning']
    if arg.startswith('full'):
        result=run(arg,[sys.executable,'-m','pytest','-q',*flags,'tests'])
    elif arg=='focused':
        result=run(arg,[sys.executable,'-m','pytest','-q',*flags,'tests/test_stage63_independent_lab.py'])
    else:
        result=run(arg,[sys.executable,'-m','cybersec.stage63_host'],timeout=20)
    raise SystemExit(result['exit_code'])
