#!/usr/bin/env python3
"""macOS SSH operator for focused ZAP lab. No secrets or active/day04 commands."""
import argparse
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess
import sys
import zipfile

ROOT=Path(__file__).resolve().parent
VM='cyberadmin@192.168.64.2'
REMOTE_DIR='/home/cyberadmin/cybersec-zap-focused-v75pid'
EVIDENCE=Path.home()/'Documents/CyberSecurity_2.0/EVIDENCE'
SSH=['ssh','-o','BatchMode=yes','-o','StrictHostKeyChecking=yes','-o','ConnectTimeout=12',
     '-i',str(Path.home()/'.ssh/id_ed25519')]
SCP=['scp','-q','-o','BatchMode=yes','-o','StrictHostKeyChecking=yes','-o','ConnectTimeout=12',
     '-i',str(Path.home()/'.ssh/id_ed25519')]

def sha(p):
    h=hashlib.sha256()
    with p.open('rb') as f:
        for chunk in iter(lambda:f.read(1024*1024),b''):h.update(chunk)
    return h.hexdigest()

def verify():
    manifest=json.loads((ROOT/'SOURCE_SHA256.json').read_text())
    for rel,expected in manifest['files'].items():
        p=ROOT/rel
        if not p.is_file() or p.is_symlink() or sha(p)!=expected:
            raise RuntimeError('SOURCE_SHA256_INVALID: '+rel)
    if set(manifest['files']) != {p.relative_to(ROOT).as_posix() for p in ROOT.rglob('*')
                                  if p.is_file() and p.name!='SOURCE_SHA256.json'}:
        raise RuntimeError('SOURCE_FILESET_MISMATCH')
    print('V75PID_ZAP_FOCUSED_SOURCE_SHA256_PASS '+str(len(manifest['files'])),flush=True)

def runstep(cmd,root,name,timeout):
    try:
        p=subprocess.run(cmd,capture_output=True,timeout=timeout)
        out=p.stdout.decode('utf-8','replace')
        err=p.stderr.decode('utf-8','replace')
        code=p.returncode
    except subprocess.TimeoutExpired as e:
        code=124;out=(e.stdout or b'').decode('utf-8','replace');err=(e.stderr or b'').decode('utf-8','replace')
    (root/(name+'.stdout.txt')).write_text(out)
    (root/(name+'.stderr.txt')).write_text(err)
    (root/(name+'.exitcode')).write_text(str(code)+'\n')
    print(name+'='+('PASS' if code==0 else 'FAIL_EXIT_'+str(code)),flush=True)
    return code,out

def zip_evidence(work):
    (work/'SHA256SUMS.txt').write_text(''.join(sha(p)+'  '+p.relative_to(work).as_posix()+'\n'
         for p in sorted(work.rglob('*')) if p.is_file() and p.name!='SHA256SUMS.txt'))
    dest=work.with_suffix('.zip')
    with zipfile.ZipFile(dest,'w',zipfile.ZIP_DEFLATED,compresslevel=9) as z:
        for p in sorted(work.rglob('*')):
            if p.is_file():z.write(p,p.relative_to(work.parent))
    with zipfile.ZipFile(dest) as z:
        if z.testzip() is not None:raise RuntimeError('EVIDENCE_CRC_MISMATCH')
    dest.with_suffix('.zip.sha256').write_text(sha(dest)+'  '+dest.name+'\n')
    print('MAC_ZAP_FOCUSED_EVIDENCE='+str(dest),flush=True)

def read_operator_consent():
    """Read exact YES from an actual TTY; never accept redirected stdin.

    None means no valid terminal; any other string is the operator response.
    """
    prompt='Подтвердите выделенную разрешённую UTM-лабораторию. Введите YES: '
    stream=getattr(sys,'stdin',None)
    if stream is not None and stream.isatty():
        sys.stderr.write(prompt)
        sys.stderr.flush()
        try:
            return stream.readline().strip()
        except (OSError,ValueError):
            return None
    try:
        # /dev/tty must be opened in READ mode, not r+ (read/write).
        with open('/dev/tty','r',encoding='utf-8') as tty:
            sys.stderr.write(prompt)
            sys.stderr.flush()
            return tty.readline().strip()
    except (OSError,ValueError):
        return None

def main():
    p=argparse.ArgumentParser()
    p.add_argument('mode',choices=['review','apply'])
    args=p.parse_args()
    verify()
    if args.mode=='review':
        print('REVIEW_ONLY: ZAP API 8080 inside Docker, scoped Spider, AJAX Firefox Headless, Passive queue; no active scan')
        print('VM='+VM+' (operator-owned UTM); PRODUCTION=BLOCKED/NO-GO; STAGE71=NOT_OPENED')
        return 0
    # Require a REAL terminal. Prefer inherited stdin (Terminal.app/iTerm2),
    # then a READ-ONLY /dev/tty descriptor. Opening /dev/tty in r+ mode can
    # fail on macOS before the operator ever sees the consent prompt.
    consent=read_operator_consent()
    if consent is None:
        print('BLOCKED: interactive terminal required; run directly in macOS Terminal',file=sys.stderr)
        return 4
    if consent!='YES':
        print('BLOCKED: operator did not confirm owned isolated lab',file=sys.stderr)
        return 4
    EVIDENCE.mkdir(parents=True,exist_ok=True,mode=0o700)
    os.chmod(EVIDENCE,0o700)
    tag='ZAP_FOCUSED_MAC_V75PID_'+datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%SZ')
    work=EVIDENCE/tag
    work.mkdir(mode=0o700)
    code=4
    status={'schema':'stage70-zap-mac-v75pid-cross-phase-observed-association','production':'BLOCKED/NO-GO',
            'stage71':'NOT_OPENED','day04':'NOT_RUN','result':'BLOCKED'}
    try:
        rc,_=runstep(SSH+[VM,'mkdir -p -m 700 '+REMOTE_DIR],work,'ssh_create_dir',35)
        if rc:return 4
        rc,_=runstep(SCP+[str(ROOT/'zap_focus_vm.py'),VM+':'+REMOTE_DIR+'/zap_focus_vm.py'],
                     work,'scp_upload_runner',65)
        if rc:return 4
        rh,_=runstep(SCP+[str(ROOT/'pid_recovery.py'),VM+':'+REMOTE_DIR+'/pid_recovery.py'],
                     work,'scp_upload_pid_helper',65)
        if rh:return 4
        rc,out=runstep(SSH+[VM,'python3 '+REMOTE_DIR+'/zap_focus_vm.py --apply'],
                       work,'ubuntu_zap_focused',1100)
        status['vm_exit_code']=rc
        m=re.search(r'^FOCUSED_EVIDENCE_ZIP=(/home/cyberadmin/cybersec-zap-focused-evidence/stage70_zap_focused_v75pid_\d{8}T\d{6}Z_[a-f0-9]{8}\.zip)$',out,re.M)
        if m:
            remote=m.group(1)
            r1,_=runstep(SCP+[VM+':'+remote,str(work/'VM_ZAP_FOCUSED_EVIDENCE.zip')],work,'scp_get_vm_evidence',120)
            r2,_=runstep(SCP+[VM+':'+remote+'.sha256',str(work/'VM_ZAP_FOCUSED_EVIDENCE.zip.sha256')],work,'scp_get_vm_sha256',45)
            if r1==0 and r2==0:
                expected=(work/'VM_ZAP_FOCUSED_EVIDENCE.zip.sha256').read_text().split()[0]
                status['vm_evidence_sha256']='PASS' if sha(work/'VM_ZAP_FOCUSED_EVIDENCE.zip')==expected else 'FAIL'
                if status['vm_evidence_sha256']=='PASS':
                    with zipfile.ZipFile(work/'VM_ZAP_FOCUSED_EVIDENCE.zip') as z:
                        status['vm_evidence_crc']='PASS' if z.testzip() is None else 'FAIL'
            else:status['vm_evidence_sha256']='TRANSFER_BLOCKED'
        else:status['vm_evidence_sha256']='NO_VM_EVIDENCE_LOCATOR'
        code=0 if rc==0 and status.get('vm_evidence_sha256')=='PASS' and status.get('vm_evidence_crc')=='PASS' else 4
        status['result']='ZAP_LAB_PASS_NOT_PRODUCTION' if code==0 else 'BLOCKED'
    except Exception as e:
        status['error']=type(e).__name__
    finally:
        (work/'MAC_FOCUSED_STATUS.json').write_text(json.dumps(status,indent=2,sort_keys=True)+'\n')
        zip_evidence(work)
    return code

if __name__=='__main__':raise SystemExit(main())
