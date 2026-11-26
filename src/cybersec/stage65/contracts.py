"""Canonical domain-separated Ed25519 per-attempt, single-use scan permits.

Signing is an attester-only/offline operation; workers and brokers keep only
pinned public keys. Tokens alone never confer production execution authority.
"""
from __future__ import annotations

import base64
from dataclasses import asdict, dataclass
import hashlib
import json
import re
import time
from typing import Sequence

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey

DOMAIN = b'CYBERSEC-STAGE65-PERMIT-V1\x00'
HEX64 = re.compile(r'[0-9a-f]{64}\Z')
ID = re.compile(r'[a-zA-Z0-9][a-zA-Z0-9_.-]{0,95}\Z')
_ALLOWED_KEYS = frozenset({'schema', 'permit_id', 'attempt_id', 'argv_sha256', 'worker_uid',
                           'scope', 'issued_at', 'expires_at', 'issuer', 'generation'})

class PermitError(PermissionError):
    """A permit cannot authorize this attempt."""


def canonical_bytes(value: dict) -> bytes:
    return json.dumps(value, ensure_ascii=True, sort_keys=True, separators=(',', ':'), allow_nan=False).encode('ascii')


def argv_digest(args: Sequence[str]) -> str:
    if not args or len(args) > 256 or not all(type(x) is str and x and '\x00' not in x and len(x) <= 4096 for x in args):
        raise PermitError('Invalid immutable command manifest')
    return hashlib.sha256(DOMAIN + b'argv\x00' + canonical_bytes({'argv': list(args)})).hexdigest()


def _unique_pairs(pairs):
    out = {}
    for k, v in pairs:
        if k in out:
            raise PermitError('Duplicate JSON key')
        out[k] = v
    return out


def _b64(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).decode('ascii').rstrip('=')


def _unb64(s: str) -> bytes:
    if not isinstance(s, str) or len(s) > 128 or not re.fullmatch('[A-Za-z0-9_-]+', s):
        raise PermitError('Invalid signature encoding')
    value = base64.urlsafe_b64decode(s + '=' * (-len(s) % 4))
    if _b64(value) != s:
        raise PermitError('Noncanonical signature')
    return value


@dataclass(frozen=True)
class Permit:
    schema: str
    permit_id: str
    attempt_id: str
    argv_sha256: str
    worker_uid: int
    scope: str
    issued_at: int
    expires_at: int
    issuer: str
    generation: int

    def validate(self) -> None:
        if self.schema != 'cybersec.stage65.permit.v1':
            raise PermitError('Unsupported permit schema')
        if any(not isinstance(x, str) or ID.fullmatch(x) is None for x in
               (self.permit_id, self.attempt_id, self.issuer)):
            raise PermitError('Invalid permit identifier')
        if not isinstance(self.argv_sha256, str) or HEX64.fullmatch(self.argv_sha256) is None:
            raise PermitError('Invalid command hash')
        if not isinstance(self.scope, str) or not re.fullmatch(r'[a-zA-Z0-9][a-zA-Z0-9_./-]{0,127}', self.scope) or '..' in self.scope.split('/'):
            raise PermitError('Invalid scope')
        if type(self.worker_uid) is not int or self.worker_uid <= 0:
            raise PermitError('Invalid worker UID')
        if any(type(x) is not int for x in (self.issued_at, self.expires_at, self.generation)):
            raise PermitError('Invalid permit numeric fields')
        if self.issued_at < 1 or self.expires_at <= self.issued_at or self.expires_at-self.issued_at > 300:
            raise PermitError('Permit lifetime exceeds five minutes')
        if self.generation < 1 or self.generation > 2**63-1:
            raise PermitError('Invalid recovery generation')

    def payload(self) -> dict:
        self.validate()
        return asdict(self)


def sign_permit(permit: Permit, attester_private_key: Ed25519PrivateKey) -> str:
    """Only call in independently confined attester service; never from broker."""
    payload = permit.payload()
    signature = attester_private_key.sign(DOMAIN + canonical_bytes(payload))
    return canonical_bytes({'payload': payload, 'signature': _b64(signature)}).decode('ascii')


class PermitVerifier:
    def __init__(self, pinned_public_key: Ed25519PublicKey, *, issuer: str):
        if not issuer or not ID.fullmatch(issuer):
            raise ValueError('Pinned issuer is required')
        self.key, self.issuer = pinned_public_key, issuer

    def verify(self, token: str, *, attempt_id: str, args: Sequence[str], worker_uid: int,
               scope: str, generation: int, now: int | None = None) -> Permit:
        if not isinstance(token, str) or len(token) > 4096:
            raise PermitError('Invalid permit token length')
        try:
            envelope = json.loads(token, object_pairs_hook=_unique_pairs,
                                  parse_constant=lambda x: (_ for _ in ()).throw(PermitError('Invalid constant')))
            if not isinstance(envelope, dict) or set(envelope) != {'payload', 'signature'}:
                raise PermitError('Invalid token envelope')
            payload = envelope['payload']
            if not isinstance(payload, dict) or set(payload) != _ALLOWED_KEYS:
                raise PermitError('Unknown or missing permit field')
            permit = Permit(**payload)
            data = DOMAIN + canonical_bytes(permit.payload())
            sig = _unb64(envelope['signature'])
            if len(sig) != 64:
                raise PermitError('Invalid Ed25519 signature size')
            self.key.verify(sig, data)
        except (ValueError, TypeError, KeyError, InvalidSignature) as exc:
            raise PermitError('Invalid or unsigned permit') from exc
        actual_now = int(time.time()) if now is None else now
        if type(actual_now) is not int or not permit.issued_at <= actual_now < permit.expires_at:
            raise PermitError('Permit expired or not yet valid')
        if (permit.issuer != self.issuer or permit.attempt_id != attempt_id or
            permit.argv_sha256 != argv_digest(args) or permit.worker_uid != worker_uid or
            permit.scope != scope or permit.generation != generation):
            raise PermitError('Permit context mismatch')
        return permit
