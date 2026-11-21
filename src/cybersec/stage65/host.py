"""Live OS identity, policy and cgroup eligibility checks; always fail closed.

These observations do NOT certify successful hostile same-UID MAC confinement.
A real Ubuntu acceptance suite must supply signed external assurance before GO.
"""
from __future__ import annotations

from dataclasses import dataclass
import os
import hashlib
from pathlib import Path
import pwd
import re
import stat
import sys

from .ledger import LedgerBlocked
from cybersec.stage64_runtime import audit_host

ROLES = {'broker':'cybersec-broker', 'worker':'cybersec-worker',
         'attester':'cybersec-attester','witness':'cybersec-witness',
         'publisher':'cybersec-publisher'}

@dataclass(frozen=True)
class RoleMap:
    broker: int
    worker: int
    attester: int
    witness: int
    publisher: int

    def verify(self):
        ids=[getattr(self,role) for role in ROLES]
        if any(type(x) is not int or x<=0 for x in ids) or len(set(ids)) != len(ids):
            raise LedgerBlocked('Independent broker and four different non-root UIDs required')
        return self


def actual_role_map() -> RoleMap:
    try:
        uids={role:pwd.getpwnam(name).pw_uid for role,name in ROLES.items()}
    except KeyError as exc:
        raise LedgerBlocked('Missing required dedicated service UID') from exc
    return RoleMap(**uids).verify()


def exact_enforcing_mac(pid:int, expected_profile:str)->bool:
    try:
        label=Path(f'/proc/{pid}/attr/current').read_text(encoding='ascii').strip()
        return label == expected_profile+' (enforce)'
    except OSError: return False


def protected_file(path: Path, expected_uid: int=0) -> bool:
    """Reject writable-by-other, symlinks and untrusted ancestor directories."""
    try:
        path=path.absolute()
        for p in (path,*path.parents):
            st=p.lstat()
            if stat.S_ISLNK(st.st_mode) or st.st_uid!=expected_uid or st.st_mode & 0o022:
                return False
        return path.is_file()
    except OSError: return False


class HostAdmission:
    def __init__(self, *, expected_profile: str, fixed_cgroup: Path,
                 installed_unit: Path, approved_policy_digest: str,
                 installed_policy: Path | None = None):
        self.expected_profile=expected_profile
        self.fixed_cgroup=fixed_cgroup
        self.installed_unit=installed_unit
        self.approved_policy_digest=approved_policy_digest
        self.installed_policy=installed_policy

    def check(self, *, roles: RoleMap) -> None:
        roles.verify()
        if sys.platform!='linux' or os.geteuid()!=roles.broker:
            raise LedgerBlocked('Wrong broker OS identity')
        observed=audit_host()
        if not observed.checks['ubuntu_server_26_10'] or not observed.checks['unified_cgroup_v2'] or not observed.checks['systemd_pid1']:
            raise LedgerBlocked('Ubuntu 26.10, systemd PID1 and cgroup v2 required')
        if not exact_enforcing_mac(os.getpid(),self.expected_profile):
            raise LedgerBlocked('Broker is not under exact enforced AppArmor profile')
        if not protected_file(self.installed_unit):
            raise LedgerBlocked('Installed systemd unit not root-owned and immutable to service UIDs')
        if not re.fullmatch('[0-9a-f]{64}',self.approved_policy_digest):
            raise LedgerBlocked('Pinned policy digest missing')
        if self.installed_policy is None or not protected_file(self.installed_policy):
            raise LedgerBlocked('Protected installed MAC policy unavailable')
        if hashlib.sha256(self.installed_policy.read_bytes()).hexdigest()!=self.approved_policy_digest:
            raise LedgerBlocked('Installed MAC policy differs from pinned hash')
        if not re.fullmatch(r'[0-9a-fA-F]{32}',os.environ.get('INVOCATION_ID','')):
            raise LedgerBlocked('No independent systemd invocation proof')
        root=Path('/sys/fs/cgroup')
        try:
            d=self.fixed_cgroup.resolve(strict=True)
            if d==root or not d.is_relative_to(root) or self.fixed_cgroup.is_symlink():
                raise LedgerBlocked('Invalid delegated cgroup')
            from cybersec.process_identity import observe_process
            if observe_process(os.getpid()).cgroup!='/' + str(d.relative_to(root)):
                raise LedgerBlocked('Broker not itself in expected delegated service cgroup')
            if not d.is_dir() or not all((d/name).is_file() for name in ('cgroup.procs','cgroup.events','cgroup.kill')):
                raise LedgerBlocked('Kernel cgroup v2 controls unavailable')
            if not all(os.access(d/name,os.W_OK) for name in ('cgroup.procs','cgroup.kill')) or not os.access(d,os.W_OK):
                raise LedgerBlocked('No writable delegated cgroup authority')
        except OSError as exc:
            raise LedgerBlocked('Cgroup directory validation failed') from exc
        # No programmatic claim of host certification: kernel-negative evidence
        # plus independently signed acceptance is a separate release gate.
        raise LedgerBlocked('BLOCKED/NO-GO: independent AppArmor negative and Ubuntu lifecycle acceptance not yet certified')
