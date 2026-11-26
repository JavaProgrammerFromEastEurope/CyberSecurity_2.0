#!/usr/bin/env python3
"""Full V74 immutable baseline then V75; fail closed on all errors/timeouts."""
import sys
sys.dont_write_bytecode=True
from pathlib import Path
import tempfile,io,zipfile,subprocess,os
from restore_v74 import checked,NAME
ROOT=Path(__file__).resolve().parent
ENV={**os.environ,'PYTHONDONTWRITEBYTECODE':'1',
 'PYTHONWARNINGS':'error::ResourceWarning,error::DeprecationWarning'}
FLAGS=[sys.executable,'-B','-W','error::ResourceWarning','-W','error::DeprecationWarning']
def run(cmd,cwd,timeout):
 try:p=subprocess.run(cmd,cwd=cwd,env=ENV,capture_output=True,timeout=timeout)
 except subprocess.TimeoutExpired as e:
  sys.stdout.buffer.write(e.stdout or b'');sys.stderr.buffer.write(e.stderr or b'')
  raise SystemExit(124)
 sys.stdout.buffer.write(p.stdout);sys.stderr.buffer.write(p.stderr)
 if p.returncode:raise SystemExit(p.returncode)
with tempfile.TemporaryDirectory(prefix='v75_full_cumulative_') as td:
 with zipfile.ZipFile(io.BytesIO(checked())) as z:z.extractall(td)
 run(FLAGS+['run_strict_regressions.py'],Path(td)/NAME,900)
run(FLAGS+['-m','unittest','discover','-s','tests','-p','test_v75_pid_recovery.py','-v'],ROOT,120)
