#!/usr/bin/env python3
"""macOS launcher: verified R4->R3->V75 nesting; patch TEMP COPY only.

Never weakens Docker, seccomp, NoNewPrivs, UID, network or scanning scope.
All real A/B operations remain delegated to pinned R3/V75 operators with explicit
interactive consent and required quiescence. --mode review never runs A/B.
"""
from __future__ import annotations
import argparse, hashlib, json, os, shutil, stat, subprocess, sys, tempfile, zipfile
from pathlib import Path, PurePosixPath
from r5_compose_fix import patch_r3_autorunner

ROOT=Path(__file__).resolve().parent
PARENT='Stage70_V75_Compose_Delta_Forensics_R4_LT10MB.zip'
PIN_R4='1c4d9441739ba962b73c7bd72c31aa9f2b41ffe48c578e959cd1d3d5c259aa9c'
PIN_R3='7956839ac3dcb6800231e4dc3176947d7c972c43aea8e5c851a5a7089a7901c1'
PIN_EVIDENCE='750e5a131f64173de5145a26509f6d882b2e47dedaf98a6d184ea3f1ac71ad7c'
PIN_PASTE='56eddc53ac9791aac5ad9eca33b463c4ceb551eff5c91a3778f7f5f2ef095ea2'
R4_FOLDER='Stage70_V75_Compose_Delta_Forensics_R4_LT10MB'
R3_FOLDER='Stage70_V75_PID_Recovery_Cgroup_Root_Fix_R3'
R3_ZIP='Stage70_V75_PID_Recovery_Cgroup_Root_Fix_R3_LT10MB.zip'

def sha_file(path):
 h=hashlib.sha256()
 with path.open('rb') as f:
  for part in iter(lambda:f.read(1024*1024),b''):h.update(part)
 return h.hexdigest()

def validate_zip(p, prefix):
 if not p.is_file() or p.is_symlink():raise ValueError('SOURCE_ARCHIVE_UNAVAILABLE')
 with zipfile.ZipFile(p) as z:
  infos=z.infolist()
  if len(infos)<10 or z.testzip() is not None:raise ValueError('ZIP_CRC_INVALID')
  if len({x.filename for x in infos})!=len(infos):raise ValueError('ZIP_DUPLICATE')
  total=0
  for entry in infos:
   path=PurePosixPath(entry.filename)
   mode=(entry.external_attr>>16)&65535
   if (not path.parts or path.parts[0]!=prefix or path.is_absolute()
     or '..' in path.parts or '\\' in entry.filename or
     stat.S_ISLNK(mode) or stat.S_IFMT(mode) not in (0,stat.S_IFDIR,stat.S_IFREG)):
    raise ValueError('ZIP_UNSAFE_ENTRY')
   total+=entry.file_size
   if entry.file_size>50_000_000 or total>80_000_000:raise ValueError('ZIP_SIZE_EXCEEDED')
 return len(infos)

def verify_sources():
 expected={PARENT:PIN_R4,'EVIDENCE(20261126-194847).zip':PIN_EVIDENCE,
           'Вставленный Markdown(20261126-194953).md':PIN_PASTE}
 for name,expected_hash in expected.items():
  p=ROOT/'originals'/name
  if not p.is_file() or p.is_symlink() or sha_file(p)!=expected_hash:
   raise ValueError('ORIGINAL_SHA256_MISMATCH:'+name)
 validate_zip(ROOT/'originals'/PARENT,R4_FOLDER)
 with zipfile.ZipFile(ROOT/'originals'/'EVIDENCE(20261126-194847).zip') as evidence:
  if evidence.testzip() is not None:raise ValueError('EVIDENCE_CRC_INVALID')
 with zipfile.ZipFile(ROOT/'originals'/PARENT) as z:
  key=R4_FOLDER+'/originals/'+R3_ZIP
  if key not in z.namelist():raise ValueError('R3_LINEAGE_MISSING')
  r3_data=z.read(key)
 if hashlib.sha256(r3_data).hexdigest()!=PIN_R3:raise ValueError('R3_SHA256_MISMATCH')
 return {'schema':'stage70-v75-compose-baseline-pid-r5','sources':'PASS',
         'r4_sha256':PIN_R4,'r3_sha256':PIN_R3,'evidence_sha256':PIN_EVIDENCE,
         'production':'BLOCKED/NO-GO','day04':'NOT_RUN','stage71':'NOT_OPENED'}

def safe_extract(p,dest,prefix):
 validate_zip(p,prefix)
 with zipfile.ZipFile(p) as z:
  for item in z.infolist():
   where=dest.joinpath(*PurePosixPath(item.filename).parts)
   if item.is_dir():where.mkdir(parents=True,exist_ok=True);continue
   where.parent.mkdir(parents=True,exist_ok=True)
   with z.open(item) as inp, where.open('xb') as out:
    shutil.copyfileobj(inp,out,1024*1024)
 return dest/prefix

def run(mode, extras):
 report=verify_sources()
 print('[R5_SOURCE] original R4 / nested R3 / V75 / latest evidence SHA256 PASS',flush=True)
 if mode=='integrity':
  print(json.dumps(report,indent=2,sort_keys=True));return 0
 with tempfile.TemporaryDirectory(prefix='stage70_v75_r5_verified_') as td:
  work=Path(td)
  r4=safe_extract(ROOT/'originals'/PARENT,work,R4_FOLDER)
  r3_archive=r4/'originals'/R3_ZIP
  if sha_file(r3_archive)!=PIN_R3:raise ValueError('R3_SHA256_MISMATCH_AFTER_EXTRACT')
  r3=safe_extract(r3_archive,work,R3_FOLDER)
  if sha_file(r3/'auto_runner.py')!='6d49bbe0d95d711b433e88807f8c716c27d7c8d2b1c4c501ab7fcb613df8777c':
   raise ValueError('R3_LAUNCHER_NOT_PINNED')
  shutil.copyfile(ROOT/'r5_compose_fix.py',r3/'r5_compose_fix.py')
  result=patch_r3_autorunner(r3/'auto_runner.py')
  print('[R5_PATCH] verified temporary R3 wrapper; immutable originals untouched',flush=True)
  print('[R5_SCOPE] ONLY ZAP pids_limit & shm_size. Other config changes BLOCKED.',flush=True)
  args=['/bin/bash',str(r3/'Run_Stage70_V75_PID_Recovery.command')]
  if mode!='interactive':args+=['--mode',mode]
  args+=extras
  env=os.environ.copy();env['PYTHONDONTWRITEBYTECODE']='1';env['PYTHONUNBUFFERED']='1'
  return subprocess.run(args,cwd=r3,env=env,check=False).returncode

def main(argv=None):
 p=argparse.ArgumentParser(description='Stage70 V75 R5 verified Compose baseline fix (laboratory only)')
 p.add_argument('--mode',choices=('integrity','review','interactive','apply'),default='interactive')
 p.add_argument('--budget-a',type=int)
 p.add_argument('--budget-b',type=int)
 p.add_argument('--lab-consent',action='store_true')
 p.add_argument('--vm-snapshot-confirmed',action='store_true')
 a=p.parse_args(argv)
 extra=[]
 for name,val in [('budget-a',a.budget_a),('budget-b',a.budget_b)]:
  if val is not None:extra.extend(['--'+name,str(val)])
 if a.lab_consent:extra.append('--lab-consent')
 if a.vm_snapshot_confirmed:extra.append('--vm-snapshot-confirmed')
 if a.mode in ('integrity','review') and extra:raise ValueError('REVIEW_HAS_NO_APPLY_FLAGS')
 return run(a.mode,extra)

if __name__=='__main__':
 try:raise SystemExit(main())
 except (ValueError,OSError,zipfile.BadZipFile,RuntimeError) as e:
  print('[R5] BLOCKED: '+str(e),file=sys.stderr,flush=True)
  raise SystemExit(4)
