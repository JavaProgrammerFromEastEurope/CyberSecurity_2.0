"""Stage 63 signed recovery receipt verifier; review-only, no consumable permit.

An independent durable counter authority and TPM monotonic protection are absent
from this library; no verified receipt alone authorizes production recovery.
"""
from __future__ import annotations

import base64
import json
import re
from datetime import datetime, timezone
from pathlib import Path

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from cybersec.lab_authorization import LabAuthorizationBlocked, _read_root_pinned_file


class RecoveryAdmissionBlocked(PermissionError):
    """Independent recovery authority or monotonic state unavailable."""


def _utc(value: str) -> datetime:
    if not isinstance(value, str) or not value.endswith('Z'):
        raise RecoveryAdmissionBlocked('Recovery timestamps must be UTC Z')
    try:
        parsed = datetime.fromisoformat(value[:-1] + '+00:00')
    except ValueError as exc:
        raise RecoveryAdmissionBlocked('Malformed timestamp') from exc
    return parsed


def verify_recovery_receipt(*, receipt: dict, trusted_public_key: bytes, job_id: int,
                            attempt: int, boot_id: str, checkpoint_sha256: str,
                            at: datetime | None = None) -> dict:
    """Verify signature+scope, without accepting or consuming an OS recovery permit."""
    expected = {'schema', 'purpose', 'job_id', 'attempt', 'boot_id', 'checkpoint_sha256',
                'counter_before', 'counter_after', 'issued_utc', 'expires_utc', 'nonce'}
    if not isinstance(receipt, dict) or set(receipt) != {'payload', 'signature'}:
        raise RecoveryAdmissionBlocked('Invalid signed receipt envelope')
    p = receipt['payload']
    if not isinstance(p, dict) or set(p) != expected:
        raise RecoveryAdmissionBlocked('Invalid signed recovery receipt schema')
    if (p['schema'] != 'cybersec.recovery-receipt.v1' or p['purpose'] != 'manual-review-only'
            or type(p['job_id']) is not int or p['job_id'] != job_id
            or type(p['attempt']) is not int or attempt < 1 or p['attempt'] != attempt
            or not isinstance(boot_id, str) or not re.fullmatch(r'[0-9a-f-]{36}', boot_id)
            or p['boot_id'] != boot_id
            or not isinstance(checkpoint_sha256, str) or not re.fullmatch(r'[0-9a-f]{64}', checkpoint_sha256)
            or p['checkpoint_sha256'] != checkpoint_sha256
            or type(p['counter_before']) is not int or type(p['counter_after']) is not int
            or p['counter_before'] < 0 or p['counter_after'] <= p['counter_before']
            or not isinstance(p['nonce'], str) or not re.fullmatch(r'[0-9a-f]{32}', p['nonce'])):
        raise RecoveryAdmissionBlocked('Recovery identity, binding or monotonic sequence invalid')
    issued, expires = _utc(p['issued_utc']), _utc(p['expires_utc'])
    now = at if at is not None else datetime.now(timezone.utc)
    if now.tzinfo is None or not issued <= now < expires or not 0 < (expires-issued).total_seconds() <= 300:
        raise RecoveryAdmissionBlocked('Recovery receipt window invalid')
    try:
        if not isinstance(trusted_public_key, bytes) or len(trusted_public_key) != 32:
            raise ValueError('Invalid public key length')
        sig = base64.b64decode(receipt['signature'], validate=True)
        if len(sig) != 64:
            raise ValueError('Invalid signature size')
        blob = json.dumps(p, sort_keys=True, separators=(',', ':'), ensure_ascii=False).encode('utf-8')
        Ed25519PublicKey.from_public_bytes(trusted_public_key).verify(sig, blob)
    except (ValueError, TypeError, InvalidSignature, KeyError) as exc:
        raise RecoveryAdmissionBlocked('Recovery signature invalid') from exc
    return dict(p)


def require_independent_recovery_admission(*, receipt: dict, job_id: int, attempt: int,
                                           boot_id: str, checkpoint_sha256: str) -> None:
    """Verify host-installed independent public key then always deny without CAS root.

    Caller MUST NOT treat a verified signed receipt as a one-time permit. The
    monotonic counter must be atomically consumed by a separate authority.
    """
    try:
        pin = _read_root_pinned_file(Path('/etc/cybersec/trust/recovery_ed25519.pub'), limit=256)
        pub = base64.b64decode(pin.strip(), validate=True)
    except (ValueError, LabAuthorizationBlocked) as exc:
        raise RecoveryAdmissionBlocked('Missing independent recovery trust root') from exc
    verify_recovery_receipt(receipt=receipt, trusted_public_key=pub,
                            job_id=job_id, attempt=attempt, boot_id=boot_id,
                            checkpoint_sha256=checkpoint_sha256)
    raise RecoveryAdmissionBlocked('No independently attested TPM counter CAS/permit consumption')
