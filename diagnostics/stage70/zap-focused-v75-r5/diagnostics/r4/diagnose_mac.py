#!/usr/bin/env python3
"""macOS authenticated remote read-only compose diff telemetry, fail closed."""
from __future__ import annotations
import argparse,fcntl,hashlib,json,os,signal,subprocess,sys,time,zipfile
from datetime import datetime,timezone
from pathlib import Path

ROOT=Path(__file__).resolve().parent
EVD=Path.home()/'Documents/CyberSecurity_2.0/EVIDENCE'
R3=ROOT/'originals/Stage70_V75_PID_Recovery_Cgroup_Root_Fix_R3_LT10MB.zip'
USER=ROOT/'originals/EVIDENCE(20261126-193829).zip'
PIN_R3='7956839ac3dcb6800231e4dc3176947d7c972c43aea8e5c851a5a7089a7901c1'
PIN_EVD='1fbf59d9b9f65e2c87b28ea73aa0adbd5f95d8007ebc6bae8c4eae38739376c7'
SSH_HOST='cyberadmin@192.168.64.2'
SCHEMA='stage70-v75-compose-delta-readonly-mac-r4'

class Blocked(Exception):pass

def sha(path):
    h=hashlib.sha256()
    with open(path,'rb') as file:
        for chunk in iter(lambda:file.read(1024*1024),b''):h.update(chunk)
    return h.hexdigest()

def require(c,reason):
    if not c:raise Blocked(reason)

def validate_sources():
    for p,d in ((R3,PIN_R3),(USER,PIN_EVD)):
        require(p.is_file() and not p.is_symlink() and sha(p)==d,'PINNED_SOURCE_INVALID')
        with zipfile.ZipFile(p) as z:require(z.testzip() is None,'PINNED_SOURCE_CRC_INVALID')
    return {'r3_sha256':PIN_R3,'new_evidence_sha256':PIN_EVD,'status':'PASS'}

def file_zip(record):
    files=sorted(p for p in record.rglob('*') if p.is_file() and p.name!='SHA256SUMS.txt')
    sums=record/'SHA256SUMS.txt';sums.write_text(''.join(f'{sha(p)}  {p.relative_to(record).as_posix()}\n' for p in files))
    dest=record.with_suffix('.zip')
    with zipfile.ZipFile(dest,'w',zipfile.ZIP_DEFLATED,compresslevel=9) as z:
        for p in sorted(record.rglob('*')):
            if p.is_file():z.write(p,p.relative_to(record.parent))
    with zipfile.ZipFile(dest) as z:require(z.testzip() is None,'EVIDENCE_ZIP_CRC')
    dest.with_suffix('.zip.sha256').write_text(f'{sha(dest)}  {dest.name}\n')
    return dest

def remote_call(code:str,timeout=110,print_heartbeat=True):
    require(isinstance(code,str) and 'docker' in code and len(code)<25000,'INVALID_REMOTE_PROBE')
    args=['ssh','-o','BatchMode=yes','-o','StrictHostKeyChecking=yes','-o','ConnectTimeout=12',
          '-i',str(Path.home()/'.ssh/id_ed25519'),SSH_HOST,'python3 -B -']
    p=subprocess.Popen(args,stdin=subprocess.PIPE,stdout=subprocess.PIPE,stderr=subprocess.PIPE,
                       start_new_session=True)
    begin=time.monotonic();inp=code.encode('utf-8'); out=b'';err=b''
    while True:
        remain=timeout-(time.monotonic()-begin)
        if remain<=0:
            try:os.killpg(p.pid,signal.SIGTERM)
            except ProcessLookupError:pass
            try:p.wait(timeout=5)
            except subprocess.TimeoutExpired:
                try:os.killpg(p.pid,signal.SIGKILL)
                except ProcessLookupError:pass
                p.wait()
            raise Blocked('SSH_PROBE_TIMEOUT')
        try:
            out,err=p.communicate(input=inp,timeout=min(8,max(0.05,remain)))
            break
        except subprocess.TimeoutExpired:
            inp=None
            if print_heartbeat:print('[REMOTE_COMPOSE_CONFIG] RUNNING elapsed=%ds; no Docker mutation'%(time.monotonic()-begin),flush=True)
    require(p.returncode==0,'SSH_OR_REMOTE_READONLY_PREFLIGHT_BLOCKED')
    require(len(out)<40000 and out.strip().startswith(b'{'),'SANITIZED_REPORT_INVALID')
    try:obj=json.loads(out)
    except (ValueError,UnicodeError):raise Blocked('SANITIZED_REPORT_JSON_INVALID')
    require(type(obj) is dict and obj.get('schema')=='stage70-v75-compose-delta-readonly-r4'
            and obj.get('outputs_sanitized') is True,'SANITIZED_SCHEMA_INVALID')
    # No raw stderr or complete Docker JSON are returned or persisted.
    return obj

def workflow(mode):
    s=validate_sources()
    print('[SOURCE] R3 original immutable SHA-256 PASS; Ubuntu evidence SHA-256 PASS',flush=True)
    if mode=='review':
        print('[REVIEW_ONLY] no SSH, no Docker config, no A/B; PRODUCTION=BLOCKED/NO-GO')
        return 0
    require(sys.platform=='darwin','MACOS_REQUIRED_FOR_REMOTE_DIAGNOSIS')
    require(sys.stdin.isatty(),'INTERACTIVE_TERMINAL_REQUIRED')
    require(input('Разрешить SSH и только Docker Compose config в своей UTM-VM? Введите READONLY: ').strip()=='READONLY',
            'READONLY_CONSENT_REQUIRED')
    EVD.mkdir(parents=True,exist_ok=True,mode=0o700)
    os.chmod(EVD,0o700)
    lock=EVD/'.STAGE70_V75_PID_AUTORUN.lock'
    fd=os.open(lock,os.O_CREAT|os.O_RDWR|os.O_NOFOLLOW,0o600)
    try:
        try:fcntl.flock(fd,fcntl.LOCK_EX|fcntl.LOCK_NB)
        except BlockingIOError:raise Blocked('CONCURRENT_AUTORUN_BLOCKED')
        record=EVD/('STAGE70_V75_COMPOSE_DELTA_R4_'+datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%SZ'))
        record.mkdir(mode=0o700)
        summary={'schema':SCHEMA,'production':'BLOCKED/NO-GO','day04':'NOT_RUN',
                 'stage71':'NOT_OPENED','pid_ab':'NOT_RUN','docker_mutations':'NONE','sources':s,'status':'BLOCKED'}
        rc=4
        try:
            print('[SSH] STRICT HOST KEY + BatchMode; Docker config only; budgets 256 and 384',flush=True)
            remote=(ROOT/'compose_delta_probe.py').read_text('utf-8')
            obj=remote_call(remote)
            (record/'SANITIZED_COMPOSE_DIFF.json').write_text(json.dumps(obj,indent=2,sort_keys=True)+'\n')
            summary['remote_status']=obj.get('status')
            if obj.get('status')=='DIAGNOSTIC_RECORDED_PRODUCTION_NO_GO':
                summary['status']='DIAGNOSTIC_ONLY';rc=0
                for arm,result in obj.get('arms',{}).items():
                    print('[ARM_'+arm+'] changed fields = '+str(result.get('changed_paths'))+'; only_approved='+str(result.get('changed_only_two_approved_fields')),flush=True)
            else:summary['status']='BLOCKED';summary['reason']=obj.get('blocker','REMOTE_DIAGNOSTIC_BLOCKED')
        except (OSError,ValueError,Blocked,subprocess.TimeoutExpired) as e:
            summary['reason']=str(e) if isinstance(e,Blocked) else type(e).__name__
            print('[REMOTE] BLOCKED '+summary['reason'],flush=True)
        finally:
            (record/'STATUS.json').write_text(json.dumps(summary,indent=2,sort_keys=True)+'\n')
            dest=file_zip(record)
            print('[EVIDENCE] '+str(dest),flush=True)
            print('[EVIDENCE_SHA256] '+sha(dest),flush=True)
        return rc
    finally:
        fcntl.flock(fd,fcntl.LOCK_UN);os.close(fd)

def main(argv=None):
    a=argparse.ArgumentParser();a.add_argument('--mode',choices=('review','probe'),default='probe')
    args=a.parse_args(argv)
    try:return workflow(args.mode)
    except (Blocked,OSError,ValueError,zipfile.BadZipFile) as e:
        print('BLOCKED: '+(str(e) if isinstance(e,Blocked) else type(e).__name__),file=sys.stderr,flush=True)
        return 4

if __name__=='__main__':raise SystemExit(main())
