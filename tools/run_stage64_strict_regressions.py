"""Stage64 strict runner, preserves both PASS and FAIL stdout/stderr/evidence."""
from __future__ import annotations
import argparse, hashlib, json, os, pathlib, subprocess, sys, time
p=argparse.ArgumentParser();p.add_argument('--project',required=True);p.add_argument('--runs',type=int,default=3)
a=p.parse_args();root=pathlib.Path(a.project);folder=root/'evidence'/'stage64';folder.mkdir(exist_ok=True,parents=True)
env=os.environ.copy();env['PYTHONPATH']=str(root/'src');env['PYTHONWARNINGS']='error::ResourceWarning,error::DeprecationWarning'
for k in ('CYBERSEC_EXECUTION_MODE','CYBERSEC_RUNTIME_MODE','CYBERSEC_UBUNTU_2610_TESTS'):env.pop(k,None)
records=[]
for ix in range(1,a.runs+1):
 name=f'strict_full_{ix}';cmd=[sys.executable,'-W','error::ResourceWarning','-W','error::DeprecationWarning','-m','pytest','-q','-ra','--tb=short','tests'];start=time.monotonic();timed_out=False
 try:
  result=subprocess.run(cmd,cwd=root,env=env,capture_output=True,text=True,errors='replace',timeout=160,check=False);out,err,code=result.stdout,result.stderr,result.returncode
 except subprocess.TimeoutExpired as exc:
  timed_out=True;out=exc.stdout.decode('utf-8','replace') if isinstance(exc.stdout,bytes) else (exc.stdout or '');err=exc.stderr.decode('utf-8','replace') if isinstance(exc.stderr,bytes) else (exc.stderr or '');code=124
 delta=round(time.monotonic()-start,3)
 (folder/f'{name}.stdout.log').write_text(out,encoding='utf-8');(folder/f'{name}.stderr.log').write_text(err,encoding='utf-8');(folder/f'{name}.exitcode').write_text(str(code)+'\n',encoding='ascii')
 row={'name':name,'argv':cmd,'exit_code':code,'seconds':delta,'timed_out':timed_out,'classification':'PASS' if code==0 and not timed_out else 'FAIL/TIMEOUT' if timed_out else 'FAIL','stdout_sha256':hashlib.sha256(out.encode()).hexdigest(),'stderr_sha256':hashlib.sha256(err.encode()).hexdigest(),'last_lines':out.splitlines()[-3:]}
 records.append(row);(folder/'regression_runs.json').write_text(json.dumps(records,indent=2,ensure_ascii=False)+'\n',encoding='utf-8');print(json.dumps(row,ensure_ascii=False),flush=True)
