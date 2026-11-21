"""Cross-UID Unix-socket witness CAS with SQLite crash durability.

Durability covers normal process crash and fsync-backed restart. Disk rollback
by a privileged adversary still requires TPM/externally monotonic authority;
this socket/database alone is NOT a hardware anti-rollback root.
"""
from __future__ import annotations

import json
import os
from pathlib import Path
import socket
import sqlite3
from contextlib import contextmanager
import struct
import threading

from .ledger import WitnessHead, LedgerBlocked, ZERO
from .contracts import canonical_bytes

MAX_MESSAGE = 4096

def _head(raw):
    if (not isinstance(raw, dict) or set(raw) != {'seq','digest'} or
        type(raw['seq']) is not int or not (0 <= raw['seq'] <= 2**63-1) or
        not isinstance(raw['digest'],str) or len(raw['digest']) != 64 or
        any(ch not in '0123456789abcdef' for ch in raw['digest'])):
        raise LedgerBlocked('Invalid witness head')
    return WitnessHead(**raw)


def _encode(head: WitnessHead) -> dict:
    return {'seq': head.seq, 'digest': head.digest}


def peer_uid(conn: socket.socket) -> int:
    if not hasattr(socket,'SO_PEERCRED'):
        raise LedgerBlocked('Kernel peer credentials unavailable')
    pid, uid, gid = struct.unpack('3i', conn.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED, struct.calcsize('3i')))
    if pid <= 0 or uid <= 0 or gid < 0:
        raise LedgerBlocked('Invalid kernel peer credential')
    return uid


class WitnessStore:
    def __init__(self, path: Path):
        self.path = Path(path)
        self.path.parent.mkdir(parents=True,exist_ok=True)
        with self._connect() as c:
            c.execute('PRAGMA journal_mode=WAL')
            c.execute('CREATE TABLE IF NOT EXISTS monotonic_head (singleton INTEGER PRIMARY KEY CHECK(singleton=1), seq INTEGER NOT NULL, digest TEXT NOT NULL)')
            c.execute('INSERT OR IGNORE INTO monotonic_head VALUES (1,0,?)',(ZERO,))

    @contextmanager
    def _connect(self):
        c=sqlite3.connect(self.path,timeout=5,isolation_level=None)
        try:
            c.execute('PRAGMA busy_timeout=5000')
            c.execute('PRAGMA synchronous=FULL')
            yield c
        finally:
            c.close()

    def read(self):
        with self._connect() as c:
            return WitnessHead(*c.execute('SELECT seq,digest FROM monotonic_head WHERE singleton=1').fetchone())

    def compare_and_swap(self,prior:WitnessHead,proposed:WitnessHead)->bool:
        _head(_encode(prior))
        _head(_encode(proposed))
        if proposed.seq != prior.seq+1:
            return False
        with self._connect() as c:
            c.execute('BEGIN IMMEDIATE')
            try:
                result=c.execute('UPDATE monotonic_head SET seq=?, digest=? WHERE singleton=1 AND seq=? AND digest=?',
                                 (proposed.seq,proposed.digest,prior.seq,prior.digest))
                c.execute('COMMIT')
                return result.rowcount == 1
            except BaseException:
                c.execute('ROLLBACK')
                raise


class WitnessServer:
    """Run under separate cybersec-witness UID with authenticated broker UID."""
    def __init__(self, socket_path: Path, store: WitnessStore, *, allowed_broker_uid: int, socket_group_gid: int | None = None):
        if allowed_broker_uid <= 0 or allowed_broker_uid == os.geteuid():
            raise LedgerBlocked('Witness must use a distinct UID from broker')
        self.socket_path=Path(socket_path)
        self.store=store
        self.allowed_broker_uid=allowed_broker_uid
        self.socket_group_gid=socket_group_gid

    def serve(self, stop: threading.Event):
        if self.socket_path.exists() or self.socket_path.is_symlink():
            raise LedgerBlocked('Refuse to unlink or overwrite existing socket')
        self.socket_path.parent.mkdir(parents=True,exist_ok=True)
        sock=socket.socket(socket.AF_UNIX,socket.SOCK_STREAM)
        try:
            sock.bind(str(self.socket_path))
            if self.socket_group_gid is not None:
                os.chown(self.socket_path,-1,self.socket_group_gid)
            os.chmod(self.socket_path,0o660 if self.socket_group_gid is not None else 0o600)
            sock.listen(16)
            sock.settimeout(.2)
            while not stop.is_set():
                try: conn,_=sock.accept()
                except socket.timeout: continue
                with conn:
                    conn.settimeout(2)
                    try:
                        if peer_uid(conn) != self.allowed_broker_uid:
                            raise LedgerBlocked('Peer UID denied')
                        raw=bytearray()
                        while b'\n' not in raw and len(raw) <= MAX_MESSAGE:
                            piece=conn.recv(min(1024,MAX_MESSAGE+1-len(raw)))
                            if not piece: break
                            raw.extend(piece)
                        if len(raw)>MAX_MESSAGE or raw.count(b'\n')!=1 or not raw.endswith(b'\n'):
                            raise LedgerBlocked('Witness request framing invalid')
                        data=json.loads(raw)
                        if not isinstance(data,dict):
                            raise LedgerBlocked('Witness request must be a JSON object')
                        if data.get('action')=='read' and set(data)=={'action'}:
                            response={'ok':True,'head':_encode(self.store.read())}
                        elif data.get('action')=='cas' and set(data)=={'action','prior','proposed'}:
                            response={'ok':True,'changed':self.store.compare_and_swap(_head(data['prior']),_head(data['proposed']))}
                        else:
                            raise LedgerBlocked('Witness command denied')
                    except (LedgerBlocked,ValueError,KeyError,OSError,TypeError) as exc:
                        response={'ok':False,'error':type(exc).__name__}
                    try: conn.sendall(canonical_bytes(response)+b'\n')
                    except OSError: pass  # client disconnect cannot grant authority
        finally:
            sock.close()
            try:
                if self.socket_path.is_socket(): self.socket_path.unlink()
            except OSError: pass


class SocketWitnessAnchor:
    """Client refuses wrong peer UID; remote claims alone are not TPM assurance."""
    test_only=False
    def __init__(self, path: Path, *, expected_witness_uid: int):
        if expected_witness_uid <= 0:
            raise LedgerBlocked('Explicit independent witness UID required')
        self.path=Path(path)
        self.expected_witness_uid=expected_witness_uid

    def _query(self,request:dict)->dict:
        if self.path.is_symlink():
            raise LedgerBlocked('Witness socket symlink denied')
        with socket.socket(socket.AF_UNIX,socket.SOCK_STREAM) as c:
            c.settimeout(2)
            c.connect(str(self.path))
            if peer_uid(c)!=self.expected_witness_uid:
                raise LedgerBlocked('Unexpected witness peer UID')
            c.sendall(canonical_bytes(request)+b'\n')
            out=bytearray()
            while b'\n' not in out and len(out)<=MAX_MESSAGE:
                frag=c.recv(min(1024,MAX_MESSAGE+1-len(out)))
                if not frag: break
                out.extend(frag)
            if len(out)>MAX_MESSAGE or not out.endswith(b'\n') or out.count(b'\n')!=1:
                raise LedgerBlocked('Invalid witness reply framing')
            data=json.loads(out)
            if type(data) is not dict or data.get('ok') is not True:
                raise LedgerBlocked('Witness rejected operation')
            return data

    def read(self)->WitnessHead:
        return _head(self._query({'action':'read'})['head'])

    def compare_and_swap(self,prior:WitnessHead,proposed:WitnessHead)->bool:
        r=self._query({'action':'cas','prior':_encode(prior),'proposed':_encode(proposed)})
        if type(r.get('changed')) is not bool: raise LedgerBlocked('Invalid witness CAS reply')
        return r['changed']
