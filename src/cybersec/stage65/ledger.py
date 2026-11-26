"""Crash-consistent one-use permit claims with external monotonic witness CAS.

Independent root is REQUIRED for meaningful rollback detection. InMemoryAnchor
is test-only, never a deployment credential. The sequence is DB intent ->
witness CAS -> DB finalize, with fail-closed uncertain outcomes on any failure.
"""
from __future__ import annotations

from dataclasses import dataclass
import hashlib
import json
from pathlib import Path
import sqlite3
from contextlib import contextmanager
from typing import Protocol

from .contracts import canonical_bytes, Permit

ZERO = '0'*64

class LedgerBlocked(PermissionError):
    pass


@dataclass(frozen=True)
class WitnessHead:
    seq: int
    digest: str


class MonotonicAnchor(Protocol):
    def read(self) -> WitnessHead: ...
    def compare_and_swap(self, prior: WitnessHead, proposed: WitnessHead) -> bool: ...


class InMemoryAnchor:
    """Deterministic *test-only* anchor, not durable across machine loss."""
    test_only = True
    def __init__(self):
        self.head = WitnessHead(0, ZERO)
    def read(self) -> WitnessHead:
        return self.head
    def compare_and_swap(self, prior: WitnessHead, proposed: WitnessHead) -> bool:
        if self.head != prior or proposed.seq != prior.seq + 1:
            return False
        self.head = proposed
        return True


class WitnessLedger:
    """One-use durable local intent journal; remote witness must be independent.

    Serialized SQLite BEGIN IMMEDIATE claims stop same-ledger concurrent replay.
    Never dispatch a child until a claim is committed and externally witnessed.
    A previously committed claim remains used after a service restart.
    """
    def __init__(self, database: Path, anchor: MonotonicAnchor):
        self.database = Path(database)
        self.anchor = anchor
        self.database.parent.mkdir(parents=True, exist_ok=True)
        self._initialize()

    @contextmanager
    def _connect(self):
        c = sqlite3.connect(self.database, timeout=5, isolation_level=None)
        try:
            c.execute('PRAGMA busy_timeout=5000')
            c.execute('PRAGMA synchronous=FULL')
            yield c
        finally:
            c.close()

    def _initialize(self):
        with self._connect() as c:
            c.execute('PRAGMA journal_mode=WAL')
            c.execute('CREATE TABLE IF NOT EXISTS head (singleton INTEGER PRIMARY KEY CHECK(singleton=1), seq INTEGER NOT NULL, digest TEXT NOT NULL)')
            c.execute('CREATE TABLE IF NOT EXISTS claims (permit_id TEXT PRIMARY KEY, attempt_id TEXT NOT NULL, seq INTEGER NOT NULL UNIQUE, digest TEXT NOT NULL, status TEXT NOT NULL CHECK(status IN (\'pending\',\'used\',\'aborted\')))')
            c.execute('INSERT OR IGNORE INTO head VALUES (1, 0, ?)', (ZERO,))

    @staticmethod
    def _row_head(c) -> WitnessHead:
        seq, digest = c.execute('SELECT seq,digest FROM head WHERE singleton=1').fetchone()
        return WitnessHead(seq, digest)

    def recover(self) -> WitnessHead:
        """Finalize a witnessed pending claim, refuse divergence or old DB.

        Unwitnessed pending is retired, not reused, because its side effects
        cannot be proven absent from a crashed caller.
        """
        with self._connect() as c:
            c.execute('BEGIN IMMEDIATE')
            try:
                local = self._row_head(c)
                pending = c.execute('SELECT permit_id,seq,digest FROM claims WHERE status=?', ('pending',)).fetchall()
                remote = self.anchor.read()
                if len(pending) > 1:
                    raise LedgerBlocked('Multiple pending witness phases')
                if not pending:
                    if local != remote:
                        raise LedgerBlocked('Ledger rollback or witness divergence')
                else:
                    pid, seq, digest = pending[0]
                    expected = WitnessHead(seq, digest)
                    if remote == expected and seq == local.seq+1:
                        c.execute('UPDATE claims SET status=? WHERE permit_id=?', ('used',pid))
                        c.execute('UPDATE head SET seq=?,digest=? WHERE singleton=1', (seq,digest))
                        local = expected
                    elif remote == local and seq == local.seq+1:
                        c.execute('UPDATE claims SET status=? WHERE permit_id=?', ('aborted',pid))
                    else:
                        raise LedgerBlocked('Unrecoverable anchor/intent mismatch')
                c.execute('COMMIT')
                return local
            except BaseException:
                c.execute('ROLLBACK')
                raise

    def consume(self, permit: Permit) -> WitnessHead:
        permit.validate()
        # Reconcile any uncertain previous invocation before claiming another.
        self.recover()
        with self._connect() as c:
            c.execute('BEGIN IMMEDIATE')
            try:
                local = self._row_head(c)
                if local != self.anchor.read():
                    raise LedgerBlocked('Rollback detected before permit consumption')
                if c.execute('SELECT 1 FROM claims WHERE permit_id=? OR attempt_id=?',
                             (permit.permit_id, permit.attempt_id)).fetchone():
                    raise LedgerBlocked('Permit replay or attempted scope reuse')
                sequence = local.seq + 1
                digest = hashlib.sha256(bytes.fromhex(local.digest) + canonical_bytes({
                    'seq': sequence, 'permit_id': permit.permit_id,
                    'attempt_id': permit.attempt_id, 'generation': permit.generation,
                    'argv_sha256': permit.argv_sha256})).hexdigest()
                proposed = WitnessHead(sequence, digest)
                c.execute('INSERT INTO claims VALUES (?,?,?,?,?)',
                          (permit.permit_id,permit.attempt_id,sequence,digest,'pending'))
                c.execute('COMMIT')
            except BaseException:
                c.execute('ROLLBACK')
                raise
        # Outside the DB TX to avoid deadlocks between different authorities.
        # CAS failure leaves pending durable and retires it on recover().
        if not self.anchor.compare_and_swap(local, proposed):
            raise LedgerBlocked('Witness CAS rejected; uncertain permit, do not dispatch')
        # The external witness has advanced: crash here is recovered to USED.
        return self.recover()

    def status(self, permit_id: str) -> str | None:
        with self._connect() as c:
            row = c.execute('SELECT status FROM claims WHERE permit_id=?', (permit_id,)).fetchone()
            return row[0] if row else None
