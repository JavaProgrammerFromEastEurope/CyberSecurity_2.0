"""Independent cross-UID admission broker and kernel cgroup pre-exec primitive.

The runtime host acceptance gate deliberately returns NO-GO until independently
verified kernel negative tests and signed deployment approval are integrated.
Never let a same-UID legacy caller mint permits or select arbitrary binaries.
"""
from __future__ import annotations

import json
import os
from pathlib import Path
import re
import selectors
import signal
import socket
import subprocess
import sys
import time
from typing import Mapping, Sequence

from cybersec.process_identity import observe_process, read_population
from .contracts import PermitVerifier, PermitError, argv_digest, canonical_bytes
from .host import HostAdmission, RoleMap
from .ledger import LedgerBlocked, WitnessLedger, InMemoryAnchor
from .witness import peer_uid

MAX_REQUEST = 8192


def _root_scope(root: Path, permit_id: str) -> tuple[Path,str]:
    if not re.fullmatch(r'[a-zA-Z0-9_.-]{1,96}',permit_id):
        raise LedgerBlocked('Invalid permit ID for cgroup scope')
    trusted=Path('/sys/fs/cgroup').resolve()
    parent=root.resolve(strict=True)
    if parent==trusted or not parent.is_relative_to(trusted) or root.is_symlink():
        raise LedgerBlocked('Invalid delegated cgroup parent')
    return parent / ('scan-' + permit_id), '/' + str((parent / ('scan-' + permit_id)).relative_to(trusted))


def _kill_scope(child: Path, *, max_wait: float=3.0):
    """Use kernel subtree kill rather than PGID; any ambiguity => NO-GO."""
    if not (child/'cgroup.kill').is_file():
        raise LedgerBlocked('cgroup.kill unavailable, cannot prove descendant extinction')
    (child/'cgroup.kill').write_text('1\n',encoding='ascii')
    deadline=time.monotonic()+max_wait
    while time.monotonic()<deadline:
        current=read_population(child)
        if current is False: return
        if current is None: break
        time.sleep(.02)
    raise LedgerBlocked('No kernel proof of empty scanner cgroup')


class KernelCgroupBroker:
    """No privilege escalation; runs only when independently delegated by PID1.

    The subprocess starts an installed Python trampoline; scanner exec is held
    on a close-on-error gate until kernel cgroup placement is observed. OS MAC
    MUST prevent the child from migrating after release.
    """
    def __init__(self, delegated: Path):
        self.delegated=Path(delegated)

    def recover_orphans(self) -> list[str]:
        if self.delegated.is_symlink() or not self.delegated.is_dir():
            raise LedgerBlocked('Missing delegated cgroup during cold recovery')
        names=[]
        for child in sorted(self.delegated.iterdir()):
            if not child.name.startswith('scan-'): continue
            if child.is_symlink() or not child.is_dir() or not re.fullmatch(r'scan-[a-zA-Z0-9_.-]{1,96}',child.name):
                raise LedgerBlocked('Unsafe cgroup entry during cold recovery')
            _kill_scope(child)
            child.rmdir()
            names.append(child.name)
        return names

    def run(self, permit_id: str, args: Sequence[str], *, timeout: float=30.0)->tuple[int,bytes,bytes]:
        if not (0 < timeout<=1800): raise ValueError('Invalid execution timeout')
        argv_digest(args)
        if not hasattr(os,'pidfd_open') or not hasattr(signal,'pidfd_send_signal'):
            raise LedgerBlocked('pidfd kernel authority missing')
        if not all((self.delegated/x).is_file() for x in ('cgroup.procs','cgroup.kill','cgroup.events')):
            raise LedgerBlocked('Cgroup v2 delegation unavailable')
        child,expected=_root_scope(self.delegated,permit_id)
        child.mkdir(mode=0o700)
        proc=None; reader=None; writer=None; pidfd=None
        error=None
        try:
            if read_population(child) is not False or not (child/'cgroup.kill').is_file():
                raise LedgerBlocked('Fresh child cgroup is not empty or killable')
            reader,writer=os.pipe()
            command=[sys.executable,'-I','-m','cybersec.stage65.trampoline',
                     '--gate-fd',str(reader),'--expected-cgroup',expected,'--',*args]
            proc=subprocess.Popen(command,stdin=subprocess.DEVNULL,stdout=subprocess.PIPE,
                                  stderr=subprocess.PIPE,start_new_session=True,close_fds=True,
                                  pass_fds=(reader,),env={'PATH':'/usr/bin:/bin','LANG':'C','LC_ALL':'C'})
            os.close(reader);reader=None
            pidfd=os.pidfd_open(proc.pid,0)
            before=observe_process(proc.pid)
            (child/'cgroup.procs').write_text(str(proc.pid)+'\n',encoding='ascii')
            after=observe_process(proc.pid)
            if before.pid!=after.pid or before.start_ticks!=after.start_ticks or after.cgroup!=expected:
                raise LedgerBlocked('PID reuse or cgroup pre-exec attach failed')
            os.write(writer,b'1');os.close(writer);writer=None
            try:
                stdout,stderr=proc.communicate(timeout=timeout)
            except subprocess.TimeoutExpired as exc:
                error=LedgerBlocked('Execution timed out; cgroup cleanup mandatory')
                raise error from exc
            if len(stdout)>4_194_304 or len(stderr)>4_194_304:
                raise LedgerBlocked('Output exceeded fixed broker limit')
            if read_population(child) is not False:
                raise LedgerBlocked('Detached descendant still exists after leader exit')
            return proc.returncode,stdout,stderr
        finally:
            if reader is not None: os.close(reader)
            if writer is not None: os.close(writer)  # trampoline sees EOF and refuses exec
            try:
                if child.exists():
                    _kill_scope(child)
                    child.rmdir()
            finally:
                if proc is not None:
                    if proc.poll() is None:
                        if pidfd is not None:
                            try: signal.pidfd_send_signal(pidfd,signal.SIGKILL)
                            except ProcessLookupError: pass
                        else: proc.kill()
                    try: proc.communicate(timeout=2)
                    except subprocess.TimeoutExpired: raise LedgerBlocked('Could not reap trampoline')
                if pidfd is not None: os.close(pidfd)


class AdmissionBroker:
    def __init__(self, *, roles:RoleMap, host:HostAdmission,
                 verifier:PermitVerifier, ledger:WitnessLedger,
                 kernel:KernelCgroupBroker, executable_allowlist:Mapping[str,Sequence[str]]):
        self.roles=roles.verify()
        self.host=host
        self.verifier=verifier
        self.ledger=ledger
        self.kernel=kernel
        # Server-configured, immutable exact argv manifests. Not user-selected.
        self.allowlist={k:tuple(v) for k,v in executable_allowlist.items()}
        for name,args in self.allowlist.items():
            if not name or not isinstance(name,str): raise LedgerBlocked('Invalid command name')
            argv_digest(args)

    def admit_and_run(self, *, caller_uid:int, command:str, token:str,
                      attempt_id:str, permit_scope:str, generation:int,
                      timeout:float=30.0):
        if type(caller_uid) is not int or caller_uid != self.roles.worker:
            raise LedgerBlocked('Kernel peer credentials do not match worker UID')
        if command not in self.allowlist: raise LedgerBlocked('Unregistered executable manifest')
        args=self.allowlist[command]
        permit=self.verifier.verify(token,attempt_id=attempt_id,args=args,
                                    worker_uid=caller_uid,scope=permit_scope,generation=generation)
        # NO kernel/process action, database consumption or scanner launch before
        # independently enforced production policy and UID admission checks.
        self.host.check(roles=self.roles)
        if isinstance(self.ledger.anchor,InMemoryAnchor):
            raise LedgerBlocked('Test-only witness cannot authorize real execution')
        self.ledger.recover()
        self.kernel.recover_orphans()  # stop orphaned execs before any new admit
        self.ledger.consume(permit)
        # Uncertain failure after consumption stays USED and is never retried.
        return self.kernel.run(permit.permit_id,args,timeout=timeout)


class UnixAdmissionServer:
    def __init__(self,path:Path, broker:AdmissionBroker, *, socket_group_gid:int | None = None):
        self.path=Path(path)
        self.broker=broker
        self.socket_group_gid=socket_group_gid

    def serve(self,stop):
        if self.path.exists() or self.path.is_symlink():
            raise LedgerBlocked('Existing broker socket: refuse overwrite')
        with socket.socket(socket.AF_UNIX,socket.SOCK_STREAM) as s:
            s.bind(str(self.path))
            if self.socket_group_gid is not None: os.chown(self.path,-1,self.socket_group_gid)
            os.chmod(self.path,0o660 if self.socket_group_gid is not None else 0o600)
            s.listen(16);s.settimeout(.2)
            try:
                while not stop.is_set():
                    try: conn,_=s.accept()
                    except socket.timeout: continue
                    with conn:
                        conn.settimeout(3)
                        response={'ok':False,'error':'BLOCKED/NO-GO'}
                        try:
                            uid=peer_uid(conn)
                            data=bytearray()
                            while b'\n' not in data and len(data)<=MAX_REQUEST:
                                frag=conn.recv(min(1024,MAX_REQUEST+1-len(data)))
                                if not frag: break
                                data.extend(frag)
                            if (len(data)>MAX_REQUEST or data.count(b'\n')!=1 or
                                not data.endswith(b'\n')):
                                raise LedgerBlocked('Invalid broker message framing')
                            request=json.loads(data)
                            if not isinstance(request,dict) or set(request)!={'command','token','attempt_id','permit_scope','generation'}:
                                raise LedgerBlocked('Unknown broker request fields')
                            code,out,err=self.broker.admit_and_run(caller_uid=uid,**request)
                            response={'ok':True,'exit_code':code,'stdout':out.decode('utf-8','replace'),
                                      'stderr':err.decode('utf-8','replace')}
                        except (LedgerBlocked,PermitError,ValueError,TypeError,KeyError,TimeoutError,OSError):
                            response={'ok':False,'error':'BLOCKED/NO-GO'}
                        try: conn.sendall(canonical_bytes(response)+b'\n')
                        except OSError: pass
            finally:
                if self.path.is_socket(): self.path.unlink()
