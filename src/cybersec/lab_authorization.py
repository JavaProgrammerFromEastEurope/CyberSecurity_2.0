"""Stage 62: externally signed, per-attempt authorization for loopback-only labs.

A local registration acknowledgment is not authorization for production scanning.
The signature's key is pinned out-of-band by the independent operator.
"""
from __future__ import annotations

import base64
import ipaddress
import json
import os
import re
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import urlsplit

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from cryptography.exceptions import InvalidSignature


class LabAuthorizationBlocked(PermissionError):
    """Fail-closed policy rejection; no external request may be started."""


def require_loopback_ip(url: str) -> None:
    parsed = urlsplit(url)
    if parsed.scheme not in ('http','https') or not parsed.hostname or parsed.username or parsed.password or parsed.fragment:
        raise LabAuthorizationBlocked('Only explicit, credential-free HTTP(S) lab targets allowed')
    try:
        host = ipaddress.ip_address(parsed.hostname)
        if not host.is_loopback:
            raise LabAuthorizationBlocked('Target is not a literal loopback IP')
        _ = parsed.port
    except ValueError as exc:
        raise LabAuthorizationBlocked('Lab target must be a literal IPv4/IPv6 loopback address') from exc


def _parse_utc(value: str) -> datetime:
    if not isinstance(value,str) or not value.endswith('Z'):
        raise LabAuthorizationBlocked('Permit timestamps must use UTC Z')
    try:
        result = datetime.fromisoformat(value[:-1]+'+00:00')
    except ValueError as exc:
        raise LabAuthorizationBlocked('Malformed permit timestamp') from exc
    return result


def verify_lab_ticket(*, ticket: dict, pinned_public_key: bytes, job_id: int,
                      attempt: int, tool: str, target_url: str,
                      at: datetime | None = None) -> dict:
    """Verify an independent Ed25519 ticket binding exactly one job attempt.

    This checks only the authorization *artifact*, not the provenance of its key,
    the state of external hardware, or any cgroup/LSM enforcement.
    """
    require_loopback_ip(target_url)
    if not isinstance(ticket,dict) or set(ticket) != {'payload','signature'}:
        raise LabAuthorizationBlocked('Unexpected signed ticket schema')
    data = ticket['payload']
    required = {'schema','job_id','attempt','tool','target_url','issued_utc','expires_utc','nonce','purpose'}
    if not isinstance(data,dict) or set(data) != required:
        raise LabAuthorizationBlocked('Incomplete or extended ticket payload')
    if (data['schema'] != 'cybersec.lab-attempt.v1' or data['purpose'] != 'authorized-loopback-lab'
            or type(data['job_id']) is not int or type(data['attempt']) is not int
            or data['job_id'] != job_id or data['attempt'] != attempt or attempt < 1
            or data['tool'] != tool or tool != 'nuclei' or data['target_url'] != target_url
            or not isinstance(data['nonce'],str) or re.fullmatch(r'[0-9a-f]{32}',data['nonce']) is None):
        raise LabAuthorizationBlocked('Ticket not bound to exact authorized scan attempt')
    issued = _parse_utc(data['issued_utc'])
    expires = _parse_utc(data['expires_utc'])
    now = at if at is not None else datetime.now(timezone.utc)
    if now.tzinfo is None or not issued <= now < expires or (expires-issued).total_seconds() > 3600:
        raise LabAuthorizationBlocked('Lab authorization ticket expired, not yet valid or overlong')
    try:
        if len(pinned_public_key) != 32:
            raise ValueError('Key pin length')
        sig = base64.b64decode(ticket['signature'],validate=True)
        if len(sig) != 64:
            raise ValueError('Signature length')
        body = json.dumps(data,sort_keys=True,separators=(',',':'),ensure_ascii=False).encode('utf-8')
        Ed25519PublicKey.from_public_bytes(pinned_public_key).verify(sig,body)
    except (ValueError,TypeError,AttributeError,KeyError,InvalidSignature) as exc:
        # Catch cryptographic InvalidSignature and malformed-key errors uniformly.
        raise LabAuthorizationBlocked('Independent Ed25519 ticket verification failed') from exc
    return dict(data)


def _read_root_pinned_file(path: Path, *, limit: int) -> bytes:
    try:
        fd = os.open(path,os.O_RDONLY | getattr(os,'O_NOFOLLOW',0) | getattr(os,'O_CLOEXEC',0))
        try:
            stat = os.fstat(fd)
            if stat.st_uid != 0 or stat.st_mode & 0o022 or not __import__('stat').S_ISREG(stat.st_mode):
                raise LabAuthorizationBlocked('Trust material must be root-owned and not group/world writable')
            body = os.read(fd,limit+1)
            if len(body)>limit:
                raise LabAuthorizationBlocked('Trust material exceeds size limit')
            return body
        finally:
            os.close(fd)
    except OSError as exc:
        raise LabAuthorizationBlocked('Independent root-owned trust material not installed') from exc


def require_host_signed_lab_ticket(*, job_id: int, attempt: int, tool: str,
                                   target_url: str) -> dict:
    """Read pinned independent authorization, refusing environment-supplied keys."""
    root = Path('/etc/cybersec')
    pin = _read_root_pinned_file(root/'trust/lab_ed25519.pub',limit=256)
    ticket = _read_root_pinned_file(root/'lab-ticket.json',limit=4096)
    try:
        public = base64.b64decode(pin.strip(),validate=True)
        doc = json.loads(ticket)
    except (ValueError,TypeError) as exc:
        raise LabAuthorizationBlocked('Malformed independent trust material') from exc
    return verify_lab_ticket(ticket=doc,pinned_public_key=public,
                             job_id=job_id,attempt=attempt,tool=tool,target_url=target_url)
