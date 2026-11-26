"""Read-only Ubuntu 26.10 host compatibility and production admission inventory.

This module never issues permits. A systemd unit, a kernel label, an environment
variable, or a positive inventory is NOT an independently proven OS MAC policy.
Only an external authority can establish that a scanner cannot bypass the
controlled entry point, migrate out of cgroup, or execute legacy code as its UID.
"""
from __future__ import annotations

from dataclasses import asdict, dataclass
import json
import os
from pathlib import Path
import platform
import pwd
import re
import shutil
import ssl
import subprocess
import sys
from typing import Any


EXPECTED_ROLES = (
    'cybersec-worker', 'cybersec-attester',
    'cybersec-witness', 'cybersec-publisher',
)


@dataclass(frozen=True)
class HostAudit:
    schema: str
    status: str
    os_release: str
    python_version: str
    openssl_version: str
    systemd_version: str | None
    checks: dict[str, bool]
    role_uids: dict[str, int | None]
    blockers: tuple[str, ...]
    production_admitted: bool
    unproven: tuple[str, ...]

    def to_dict(self) -> dict[str, Any]:
        data = asdict(self)
        data['blockers'] = list(self.blockers)
        data['unproven'] = list(self.unproven)
        return data


def _read(path: str, *, max_bytes: int = 32768) -> str:
    """Bounded observation. Never follow a proc/sys or deployment path to write."""
    try:
        with open(path, 'rb') as stream:
            data = stream.read(max_bytes + 1)
        if len(data) > max_bytes:
            return ''
        return data.decode('utf-8', errors='replace')
    except (OSError, ValueError):
        return ''


def _os_release() -> dict[str, str]:
    content = _read('/etc/os-release', max_bytes=8192)
    values: dict[str, str] = {}
    for line in content.splitlines():
        if line.startswith('#') or '=' not in line:
            continue
        key, val = line.split('=', 1)
        if re.fullmatch(r'[A-Z][A-Z0-9_]*', key):
            values[key] = val.strip('"\' ')
    return values


def _systemd_version() -> int | None:
    binary = shutil.which('systemctl')
    if not binary or not os.path.isabs(binary):
        return None
    try:
        result = subprocess.run([binary, '--version'], capture_output=True, text=True,
                                timeout=2, check=False, shell=False)
        if result.returncode != 0 or len(result.stdout) > 4096:
            return None
        first = result.stdout.splitlines()[0] if result.stdout else ''
        match = re.fullmatch(r'systemd\s+(\d+)(?:\s+.*)?', first)
        return int(match.group(1)) if match else None
    except (OSError, subprocess.TimeoutExpired, IndexError):
        return None


def _cgroup_membership() -> str | None:
    lines = [line[3:].strip() for line in _read('/proc/self/cgroup').splitlines()
             if line.startswith('0::')]
    if len(lines) != 1 or not lines[0].startswith('/') or '..' in lines[0].split('/'):
        return None
    return lines[0]


def _cgroup_v2_mounted() -> bool:
    # mountinfo fields: fixed part, ' - ', filesystem type and mount source
    for line in _read('/proc/self/mountinfo', max_bytes=131072).splitlines():
        left, sep, right = line.partition(' - ')
        if sep and len(left.split()) >= 5 and left.split()[4] == '/sys/fs/cgroup' \
                and right.startswith('cgroup2 '):
            return True
    return False


def _role_uids() -> dict[str, int | None]:
    results: dict[str, int | None] = {}
    for role in EXPECTED_ROLES:
        try:
            results[role] = pwd.getpwnam(role).pw_uid
        except KeyError:
            results[role] = None
    return results


def _root_owned_unit() -> bool:
    """Conservative check; file presence alone is not proof of installed policy."""
    path = Path('/etc/systemd/system/cybersec-scanner-worker.service')
    try:
        if path.is_symlink() or not path.is_file():
            return False
        for ancestor in (path, *path.parents):
            st = ancestor.lstat()
            if st.st_uid != 0 or st.st_mode & 0o022:
                return False
        return True
    except OSError:
        return False


def audit_host() -> HostAudit:
    distro = _os_release()
    is_target = distro.get('ID') == 'ubuntu' and distro.get('VERSION_ID') == '26.10'
    systemd = _systemd_version()
    cgroup = _cgroup_membership()
    labels = _read('/proc/self/attr/current').strip()
    lsm_stack = set(s.strip() for s in _read('/sys/kernel/security/lsm').strip().split(','))
    aa_enabled = _read('/sys/module/apparmor/parameters/enabled').strip() == 'Y'
    roles = _role_uids()
    valid_role_uids = [u for u in roles.values() if u is not None and u > 0]
    checks = {
        'ubuntu_server_26_10': is_target and platform.system() == 'Linux',
        'python_3_14': sys.version_info[:2] == (3, 14),
        'openssl_4': ssl.OPENSSL_VERSION_INFO[0] == 4,
        'systemd_261_or_newer': systemd is not None and systemd >= 261,
        'systemd_pid1': _read('/proc/1/comm').strip() == 'systemd' and Path('/run/systemd/system').is_dir(),
        'unified_cgroup_v2': bool(cgroup) and _cgroup_v2_mounted(),
        'cgroup_kill_available': bool(cgroup) and Path('/sys/fs/cgroup', cgroup.lstrip('/'), 'cgroup.kill').is_file(),
        'apparmor_kernel_enabled': 'apparmor' in lsm_stack and aa_enabled,
        'worker_apparmor_enforce_label': bool(labels) and labels.endswith('(enforce)') and 'unconfined' not in labels.lower(),
        'four_separate_service_uids': len(valid_role_uids) == len(EXPECTED_ROLES) and len(set(valid_role_uids)) == len(EXPECTED_ROLES),
        'worker_uid_matches_service': roles['cybersec-worker'] is not None and os.geteuid() == roles['cybersec-worker'],
        'root_owned_systemd_unit': _root_owned_unit(),
        'systemd_invocation_id_present': bool(re.fullmatch(r'[0-9a-fA-F]{32}', os.environ.get('INVOCATION_ID', ''))),
        'pidfd_open_available': hasattr(os, 'pidfd_open'),
        # These cannot be certified by observing one's own process or env.
        'independent_os_mac_negative_tests': False,
        'independent_admission_authority': False,
        'hardware_monotonic_recovery_permit': False,
    }
    return HostAudit(
        schema='cybersec.stage64.host-inventory.v1', status='BLOCKED/NO-GO',
        os_release=f"{distro.get('ID', 'unknown')} {distro.get('VERSION_ID', 'unknown')}",
        python_version=platform.python_version(), openssl_version=ssl.OPENSSL_VERSION,
        systemd_version=str(systemd) if systemd is not None else None,
        checks=checks, role_uids=roles,
        blockers=tuple(name for name, passed in checks.items() if not passed),
        production_admitted=False,
        unproven=(
            'same-UID legacy scanner and interpreter confinement under kernel MAC',
            'cgroup migration prevention and no setsid/double-fork escape',
            'independent live systemd restart and SIGKILL evidence on Ubuntu 26.10',
            'signed per-attempt scope permit issued by independently administered authority',
            'durable anti-rollback and one-use recovery authority',
        ),
    )


def main(argv: list[str] | None = None) -> int:
    import argparse
    parser = argparse.ArgumentParser(description='Read-only Ubuntu 26.10 host inventory (never an admission permit)')
    parser.add_argument('--require-admission', action='store_true', help='Fail closed for unit ExecStartPre (always exit 3 in Stage 64)')
    parser.parse_args(argv)
    print(json.dumps(audit_host().to_dict(), indent=2, sort_keys=True, ensure_ascii=False))
    return 3


if __name__ == '__main__':
    sys.exit(main())
