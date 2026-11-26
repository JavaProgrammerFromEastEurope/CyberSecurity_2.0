#!/usr/bin/env python3
"""macOS double-click launcher for immutable Stage70 V75 PID Recovery candidate.

Offline verification by default. Remote A/B only after explicit lab, snapshot,
operator budget and interactive consent. No sandbox or production bypasses.
"""
from __future__ import annotations
import argparse
import fcntl
import hashlib
import json
import os
import signal
import selectors
from pathlib import Path, PurePosixPath
import stat
import subprocess
import sys
import tempfile
import threading
import time
import zipfile
from root_fix_r3 import apply as apply_structural_root_fix
from datetime import datetime, timezone

BASE = 'Stage70_ZAP_API_AJAX_SPIDER_PASSIVE_FOCUSED_V75_PID_BUDGET_CAUSALITY_RECOVERY_CANDIDATE_LT10MB'
ORIGINAL_SHA256 = '11d3add1a47a86a14ba9cb652e8f3a4261a499d1139d27a968d8063b23059d18'
ROOT = Path(__file__).resolve().parent
ARCHIVE = ROOT / (BASE + '.zip')
CHECKSUM = ROOT / (BASE + '.zip.sha256')
EVIDENCE = Path.home() / 'Documents' / 'CyberSecurity_2.0' / 'EVIDENCE'
MAX_UNPACKED = 50_000_000

class Blocked(RuntimeError):
    pass

def require(condition, reason):
    if not condition:
        raise Blocked(reason)

def sha256(path):
    h = hashlib.sha256()
    with open(path, 'rb') as src:
        for chunk in iter(lambda: src.read(1024 * 1024), b''):
            h.update(chunk)
    return h.hexdigest()

def validate_budget(a, b):
    require(type(a) is int and type(b) is int and 64 <= a < b <= 512,
            'BUDGET_INVALID_EXPECTED_64_LE_A_LT_B_LE_512')
    return a, b

def source_check(archive=ARCHIVE, sidecar=CHECKSUM):
    require(archive.is_file() and not archive.is_symlink(), 'ORIGINAL_ZIP_NOT_FOUND')
    require(sidecar.is_file() and not sidecar.is_symlink(), 'ORIGINAL_SHA256_NOT_FOUND')
    line = sidecar.read_text(encoding='ascii').strip()
    require(line == ORIGINAL_SHA256 + '  ' + archive.name, 'SIDECAR_NOT_PINNED')
    require(sha256(archive) == ORIGINAL_SHA256, 'ORIGINAL_ZIP_SHA256_MISMATCH')
    with zipfile.ZipFile(archive) as z:
        require(z.testzip() is None, 'ORIGINAL_ZIP_CRC_FAILURE')
        members = z.infolist()
        require(len(members) > 50 and len(members) == len(set(x.filename for x in members)),
                'ZIP_MEMBERS_INVALID')
        total = 0
        for m in members:
            name = PurePosixPath(m.filename)
            require(not m.is_dir(), 'ZIP_UNEXPECTED_DIRECTORY')
            require(len(name.parts) > 1 and name.parts[0] == BASE and
                    not name.is_absolute() and '..' not in name.parts and
                    '\\' not in m.filename, 'ZIP_TRAVERSAL')
            mode = (m.external_attr >> 16) & 0xFFFF
            require(not stat.S_ISLNK(mode) and stat.S_IFMT(mode) in (0, stat.S_IFREG),
                    'ZIP_SPECIAL_FILE')
            total += m.file_size
            require(m.file_size <= MAX_UNPACKED and total <= MAX_UNPACKED,
                    'ZIP_UNCOMPRESSED_SIZE_LIMIT')
        required = {BASE + '/' + n for n in ('SOURCE_SHA256.json',
                    'mac_pid_ab_runner.py','pid_recovery.py','mac_run.py',
                    'Run_V75_AB.command','zap_focus_vm.py','restore_v74.py')}
        require(required.issubset({x.filename for x in members}), 'ZIP_RUNTIME_MISSING')
    return {'original_sha256':ORIGINAL_SHA256, 'original_bytes':archive.stat().st_size,
            'members':len(members), 'zip_crc':'PASS'}

def extract_verified(directory, archive=ARCHIVE):
    # The caller MUST have called source_check. Never expose an extracted tree
    # until the complete original ZIP hash, CRC and member checks succeed.
    require(directory.is_dir() and not directory.is_symlink(), 'EXTRACT_DIR_INVALID')
    with zipfile.ZipFile(archive) as z:
        for m in z.infolist():
            dest=directory.joinpath(*PurePosixPath(m.filename).parts)
            dest.parent.mkdir(parents=True, exist_ok=True)
            with z.open(m) as src, open(dest, 'xb') as out:
                while True:
                    block=src.read(1024*1024)
                    if not block: break
                    out.write(block)
    return directory/BASE

def _progress(record, step, event, details='', *, display=True):
    """Append-only structured progress; no raw PIDs, addresses or credentials."""
    timestamp=datetime.now(timezone.utc).isoformat(timespec='seconds')
    record_line={'time_utc':timestamp,'step':step,'event':event,'details':details}
    with (record/'PROGRESS.jsonl').open('a', encoding='utf-8') as file:
        file.write(json.dumps(record_line, ensure_ascii=False, sort_keys=True)+'\n')
        file.flush()
    if display:
        print(f'[{timestamp}] [{step}] {event} {details}'.rstrip(), flush=True)


def _terminate_local_group(proc, step, record):
    """Stop local subprocess/SSH group; remote quiescence remains UNVERIFIED."""
    if proc.poll() is not None:
        return
    _progress(record,step,'LOCAL_PROCESS_GROUP_TERMINATING',
              'Remote cleanup must be verified before any restart')
    try: os.killpg(proc.pid, signal.SIGTERM)
    except ProcessLookupError: pass
    try: proc.wait(timeout=8)
    except subprocess.TimeoutExpired:
        try: os.killpg(proc.pid, signal.SIGKILL)
        except ProcessLookupError: pass
        try: proc.wait(timeout=5)
        except subprocess.TimeoutExpired: pass


def run_command(args, step, record, timeout, heartbeat_seconds=8):
    """Stream partial prompts immediately; never wait for 1024 bytes/newline.

    - EOF/readiness handled with selectors + os.read, not buffered pipe.read(1024).
    - Child inherits the real operator TTY for the second manual YES prompt.
    - Heartbeat is independent of SSH/stdout progress, and marks timeouts.
    - Records exact stdout/stderr and exit code; no synthetic PASS on timeout.
    """
    require(isinstance(timeout, (int,float)) and 0<timeout<=4*3600,'TIMEOUT_INVALID')
    require(isinstance(heartbeat_seconds,(int,float)) and heartbeat_seconds>0,
            'HEARTBEAT_INVALID')
    stdout_path=record/(step+'.stdout.txt')
    stderr_path=record/(step+'.stderr.txt')
    deadline=time.monotonic()+timeout
    _progress(record,step,'START',f'timeout={int(timeout)}s heartbeat={heartbeat_seconds:g}s')
    rc=None
    proc=None
    with stdout_path.open('wb') as stdout, stderr_path.open('wb') as stderr:
        child_env={**os.environ,'PYTHONDONTWRITEBYTECODE':'1',
                   'PYTHONUNBUFFERED':'1',
                   'PYTHONWARNINGS':'error::ResourceWarning,error::DeprecationWarning'}
        try:
            proc=subprocess.Popen(args,stdin=None,stdout=subprocess.PIPE,
                                  stderr=subprocess.PIPE,start_new_session=True,
                                  bufsize=0,env=child_env)
            sel=selectors.DefaultSelector()
            for fd,dest,screen in ((proc.stdout,stdout,sys.stdout),
                                   (proc.stderr,stderr,sys.stderr)):
                sel.register(fd,selectors.EVENT_READ,(dest,screen))
            previous=time.monotonic()
            started=previous
            while True:
                now=time.monotonic()
                if now >= deadline:
                    rc=124
                    _progress(record,step,'TIMEOUT',f'elapsed={int(now-started)}s; FAIL_CLOSED')
                    _terminate_local_group(proc,step,record)
                    break
                if now-previous>=heartbeat_seconds:
                    elapsed=int(now-started)
                    _progress(record,step,'RUNNING',
                              f'elapsed={elapsed}s; awaiting child/SSH progress; no result yet')
                    previous=now
                events=sel.select(timeout=min(0.5,max(0.01,deadline-now))) if sel.get_map() else []
                for key,_ in events:
                    try: data=os.read(key.fileobj.fileno(),4096)
                    except OSError: data=b''
                    if data:
                        dest,screen=key.data
                        dest.write(data); dest.flush()
                        if hasattr(screen,'buffer'):
                            screen.buffer.write(data);screen.flush()
                        else:
                            screen.write(data.decode('utf-8','replace'));screen.flush()
                    else:
                        sel.unregister(key.fileobj)
                        key.fileobj.close()
                if proc.poll() is not None and not sel.get_map():
                    rc=proc.returncode
                    break
            if rc==124:
                # Preserve any output already in the pipe without hanging if a
                # descendant improperly inherited the writer FD.
                end_drain=time.monotonic()+2
                while sel.get_map() and time.monotonic()<end_drain:
                    for key,_ in sel.select(timeout=0.1):
                        try: data=os.read(key.fileobj.fileno(),4096)
                        except OSError: data=b''
                        if data:
                            dest,screen=key.data
                            dest.write(data);dest.flush()
                            if hasattr(screen,'buffer'):
                                screen.buffer.write(data);screen.flush()
                            else:
                                screen.write(data.decode('utf-8','replace'));screen.flush()
                        else:
                            sel.unregister(key.fileobj);key.fileobj.close()
            sel.close()
        except KeyboardInterrupt:
            rc=130
            _progress(record,step,'INTERRUPTED',
                      'Ctrl+C: terminating local group; remote quiescence UNVERIFIED')
            if proc is not None: _terminate_local_group(proc,step,record)
        finally:
            if proc is not None:
                for pipe in (proc.stdout,proc.stderr):
                    if pipe is not None and not pipe.closed:pipe.close()
    if rc is None: rc=124
    (record/(step+'.exitcode')).write_text(str(rc)+'\n')
    _progress(record,step,'EXIT',f'code={rc}; '+('PASS' if rc==0 else 'BLOCKED'))
    return rc

def tty_read(prompt):
    require(sys.stdin.isatty(), 'INTERACTIVE_TERMINAL_REQUIRED')
    return input(prompt).strip()

def ask_budgets():
    a=tty_read('Конечный PID-budget A (64..511, без значения по умолчанию): ')
    b=tty_read('Конечный PID-budget B (A+1..512, без значения по умолчанию): ')
    require(a.isascii() and a.isdecimal() and len(a)<=3 and
            b.isascii() and b.isdecimal() and len(b)<=3, 'BUDGET_INPUT_INVALID')
    return validate_budget(int(a),int(b))

def stamp():
    return datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%S_%fZ')

def archive_record(record):
    files=sorted(p for p in record.rglob('*') if p.is_file() and p.name!='SHA256SUMS.txt')
    (record/'SHA256SUMS.txt').write_text(''.join(sha256(p)+'  '+p.relative_to(record).as_posix()+'\n'
                                                for p in files))
    dest=record.with_suffix('.zip')
    with zipfile.ZipFile(dest,'w',zipfile.ZIP_DEFLATED,compresslevel=9) as z:
        for p in sorted(record.rglob('*')):
            if p.is_file():z.write(p,p.relative_to(record.parent))
    with zipfile.ZipFile(dest) as z:
        require(z.testzip() is None, 'AUDIT_ZIP_CRC_FAILURE')
    dest.with_suffix('.zip.sha256').write_text(sha256(dest)+'  '+dest.name+'\n')
    print('AUTO_RUNNER_EVIDENCE='+str(dest),flush=True)

def workflow(mode, budget_a, budget_b, lab_consent, snapshot):
    EVIDENCE.mkdir(parents=True,exist_ok=True,mode=0o700)
    os.chmod(EVIDENCE,0o700)
    record=EVIDENCE/('STAGE70_V75_PID_AUTORUN_'+stamp())
    record.mkdir(mode=0o700)
    report={'schema':'stage70-v75-pid-autorun-cgroup-root-fix-r3','production':'BLOCKED/NO-GO',
            'day04':'NOT_RUN','stage71':'NOT_OPENED','status':'BLOCKED',
            'mode':mode,'ab':'NOT_RUN','real_e2e':'NOT_VERIFIED'}
    rc=4
    lock_fd=None
    try:
        # Serialise local launches; concurrent A/B invalidates cgroup proof.
        lock_path=EVIDENCE/'.STAGE70_V75_PID_AUTORUN.lock'
        lock_fd=os.open(lock_path,os.O_CREAT|os.O_RDWR|os.O_NOFOLLOW,0o600)
        try:fcntl.flock(lock_fd,fcntl.LOCK_EX|fcntl.LOCK_NB)
        except BlockingIOError:raise Blocked('CONCURRENT_AUTORUN_BLOCKED')
        report['source']=source_check()
        with tempfile.TemporaryDirectory(prefix='v75pid_autorun_') as tmp:
            project=extract_verified(Path(tmp))
            _progress(record,'R3_ROOT_POLICY','PATCHING_TEMPORARY_COPY',
                      'Immutable V75 original preserved; strict structural-root exception only')
            r3_proof=apply_structural_root_fix(project,record)
            report['r3_root_policy']=r3_proof
            _progress(record,'R3_ROOT_POLICY','PATCHED_VERIFIED',
                      'Known nonroot parent missing pids files remains BLOCKED')
            tasks=[('source_manifest',[sys.executable,'-B',str(project/'mac_run.py'),'review'],90),
                   ('v74_original',[sys.executable,'-B',str(project/'restore_v74.py'),'verify'],180),
                   ('evidence_audit',[sys.executable,'-B',str(project/'audit_latest_v75_candidate.py')],180),
                   ('ab_read_only_review',[
                       '/bin/bash',str(project/'Run_V75_AB.command'), '--budget-a','64',
                       '--budget-b','65','--review'],90)]
            for idx,(name,cmd,timeout) in enumerate(tasks,1):
                _progress(record,'LOCAL_REVIEW','STEP',f'{idx}/{len(tasks)} {name}')
                step_rc=run_command(cmd,name,record,timeout)
                require(step_rc==0, 'PRECHECK_'+name+'_FAILED_'+str(step_rc))
            report['local_review']='PASS'
            if mode=='interactive':
                answer=tty_read('Локальные проверки PASS. Введите APPLY для реального лабораторного A/B или Enter для выхода: ')
                mode='apply' if answer=='APPLY' else 'review'
            if mode=='review':
                report['status']='REVIEW_PASS_NO_REMOTE_EXECUTION'
                report['reason']='AB_NOT_RUN';rc=0
            else:
                require(sys.platform=='darwin','APPLY_REQUIRES_MACOS')
                require(sys.stdin.isatty(),'INTERACTIVE_TERMINAL_REQUIRED')
                if budget_a is None or budget_b is None:
                    budget_a,budget_b=ask_budgets()
                validate_budget(budget_a,budget_b)
                print('A/B рассчитан на 6 последовательных запусков (24 наблюдения),',flush=True)
                print('НЕ нацеливайте его на публичные ресурсы или production.',flush=True)
                if not lab_consent:
                    lab_consent=(tty_read('Подтвердите владение/разрешение на лабораторию словом LAB: ')=='LAB')
                if not snapshot:
                    snapshot=(tty_read('Подтвердите существующий UTM snapshot словом SNAPSHOT: ')=='SNAPSHOT')
                require(lab_consent and snapshot,'LAB_OR_SNAPSHOT_NOT_CONFIRMED')
                report['budgets']={'a':budget_a,'b':budget_b}
                report['ab']='STARTED'
                _progress(record,'UBUNTU_AB','OPERATOR_PROMPT',
                          'The embedded runner requires another typed YES in this terminal. Do not send Ctrl+Z.')
                _progress(record,'UBUNTU_AB','PLAN',
                          '6 sequential trials / 24 roles; each VM trial may run up to 1500s')
                command=['/bin/bash',str(project/'Run_V75_AB.command'),
                         '--budget-a',str(budget_a),'--budget-b',str(budget_b),
                         '--lab-consent','--vm-snapshot-confirmed']
                outcome=run_command(command,'ubuntu_ab_real',record,4*3600)
                report['ab']='DIAGNOSTIC_FINISHED' if outcome==0 else 'BLOCKED_OR_INCOMPLETE'
                report['runner_exit_code']=outcome
                report['status']='AB_COMPLETE_PRODUCTION_NO_GO' if outcome==0 else 'BLOCKED'
                report['reason']='REAL_E2E_UNVERIFIED' if outcome==0 else 'AB_FAILED_OR_UNVERIFIED'
                rc=0 if outcome==0 else 4
    except (Blocked,ValueError,OSError,zipfile.BadZipFile,EOFError,KeyboardInterrupt) as exc:
        report['reason']=str(exc) if isinstance(exc,Blocked) else type(exc).__name__
        print('BLOCKED: '+report['reason'],file=sys.stderr)
    finally:
        if lock_fd is not None:
            fcntl.flock(lock_fd,fcntl.LOCK_UN)
            os.close(lock_fd)
        # Never silently recreate a lost evidence directory after an earlier
        # suspended instance or out-of-band cleanup. Mark as fail-closed.
        if record.is_dir() and not record.is_symlink():
            try:
                (record/'AUTORUN_STATUS.json').write_text(json.dumps(report,indent=2,sort_keys=True)+'\n')
                archive_record(record)
            except (OSError,ValueError,zipfile.BadZipFile) as exc:
                print('BLOCKED: EVIDENCE_FINALIZATION_'+type(exc).__name__,file=sys.stderr,flush=True)
                rc=4
        else:
            print('BLOCKED: EVIDENCE_DIRECTORY_REMOVED_OR_REPLACED; NO_ARCHIVE',file=sys.stderr,flush=True)
            rc=4
    return rc

def main(argv=None):
    if hasattr(signal,'SIGTSTP'):
        def no_suspend(signum,frame):
            print('\n[SECURITY] Ctrl+Z ignored: A/B may leave SSH/Firefox running. Use Ctrl+C for orderly local cancellation.',file=sys.stderr,flush=True)
        signal.signal(signal.SIGTSTP,no_suspend)
    p=argparse.ArgumentParser(description='Stage70 V75 R3 verified working-copy cgroup-root fix macOS launcher')
    p.add_argument('--mode',choices=('interactive','review','apply'),default='interactive')
    p.add_argument('--budget-a',type=int)
    p.add_argument('--budget-b',type=int)
    p.add_argument('--lab-consent',action='store_true')
    p.add_argument('--vm-snapshot-confirmed',action='store_true')
    args=p.parse_args(argv)
    if args.mode=='apply':
        require(args.budget_a is None or args.budget_b is None or
                64<=args.budget_a<args.budget_b<=512,'BUDGET_BOUNDS')
    return workflow(args.mode,args.budget_a,args.budget_b,
                    args.lab_consent,args.vm_snapshot_confirmed)

if __name__=='__main__':
    try:raise SystemExit(main())
    except Blocked as exc:
        print('BLOCKED: '+str(exc),file=sys.stderr)
        raise SystemExit(4)
