"""Stage 63 independent-host observation: evidence intake, NEVER admission.

No file produced by this module is an OS-MAC proof or a production permit.
Only pre-existing independently operated systemd, kernel, root-provisioned
trust and external authority can satisfy the corresponding prerequisites.
"""
from __future__ import annotations

import json
import os
import pwd
import re
import stat
import subprocess
import sys
from pathlib import Path
from typing import Any

from cybersec.stage62_audit import audit_host as stage62_audit

ROLES = {
    'worker': ('cybersec-worker', 'cybersec-scanner-worker.service'),
    'attester': ('cybersec-attester', 'cybersec-attester.service'),
    'witness': ('cybersec-witness', 'cybersec-witness.service'),
    'publisher': ('cybersec-publisher', 'cybersec-publisher.service'),
}
EXPECTED_SYSTEMD_PATH = Path('/etc/systemd/system')
SHA256_RE = re.compile(r'^[0-9a-f]{64}$')


def _read_limited(path: Path, limit: int = 65536) -> bytes:
    fd = os.open(path, os.O_RDONLY | getattr(os, 'O_NOFOLLOW', 0) | getattr(os, 'O_CLOEXEC', 0))
    try:
        s = os.fstat(fd)
        if not stat.S_ISREG(s.st_mode) or s.st_size > limit:
            raise ValueError('Invalid or oversized host artifact')
        out = os.read(fd, limit + 1)
        if len(out) > limit:
            raise ValueError('Host artifact exceeds size limit')
        return out
    finally:
        os.close(fd)


def _root_owned_protected_file(path: Path) -> bool:
    """Observe both file and parent security; not a substitute for MAC policy."""
    try:
        if path.is_symlink() or not path.is_file():
            return False
        current = path
        while True:
            s = current.lstat()
            if current.is_symlink() or s.st_uid != 0 or (s.st_mode & 0o022):
                return False
            if current == current.parent:
                break
            current = current.parent
        _read_limited(path)
        return True
    except (OSError, ValueError):
        return False


def _starttime_and_cgroup(pid: int) -> tuple[str, str, tuple[int, int, int, int], str]:
    stat_text = Path(f'/proc/{pid}/stat').read_text(encoding='ascii')
    closing = stat_text.rfind(')')
    if closing < 1:
        raise ValueError('Malformed /proc pid stat')
    fields = stat_text[closing+2:].split()
    starttime = fields[19]
    groups = [s[3:].strip() for s in Path(f'/proc/{pid}/cgroup').read_text(encoding='ascii').splitlines() if s.startswith('0::')]
    if len(groups) != 1:
        raise ValueError('No unique cgroup v2 membership')
    status = Path(f'/proc/{pid}/status').read_text(encoding='ascii')
    uidlines = [x for x in status.splitlines() if x.startswith('Uid:')]
    if len(uidlines) != 1:
        raise ValueError('No unique UID tuple')
    uidfields = tuple(int(x) for x in uidlines[0].split()[1:])
    if len(uidfields) != 4:
        raise ValueError('Incomplete UID tuple')
    label = Path(f'/proc/{pid}/attr/current').read_text(encoding='utf-8').strip()
    if stat_text != Path(f'/proc/{pid}/stat').read_text(encoding='ascii'):
        # Changes of accounting fields are routine, so check starttime only.
        repeat = Path(f'/proc/{pid}/stat').read_text(encoding='ascii')
        if repeat[repeat.rfind(')')+2:].split()[19] != starttime:
            raise ValueError('PID reused during inspection')
    return starttime, groups[0], uidfields, label


def _systemd_show(unit: str) -> dict[str, str]:
    if unit not in [u for _, u in ROLES.values()]:
        raise ValueError('Unknown or untrusted service name')
    if Path('/proc/1/comm').read_text().strip() != 'systemd' or not Path('/run/systemd/system').is_dir():
        raise RuntimeError('systemd PID 1 is not running')
    keys = ('Id', 'User', 'Group', 'MainPID', 'ActiveState', 'SubState', 'ControlGroup',
            'FragmentPath', 'InvocationID', 'ExecStart', 'Delegate', 'AppArmorProfile')
    result = subprocess.run(['/usr/bin/systemctl', 'show', '--no-pager',
                             '--property=' + ','.join(keys), unit],
                            text=True, capture_output=True, timeout=4, check=False)
    if result.returncode or len(result.stdout) > 32768:
        raise RuntimeError('Cannot verify installed service state')
    props: dict[str, str] = {}
    for line in result.stdout.splitlines():
        if '=' not in line:
            raise ValueError('Invalid systemd property')
        key, value = line.split('=', 1)
        if key in props:
            raise ValueError('Repeated systemd property')
        props[key] = value
    if any(key not in props for key in keys):
        raise ValueError('Missing systemd property')
    return props


def _mac_enforcement() -> dict[str, Any]:
    """Distinguish kernel LSM enforcement from a mere file or string label."""
    result: dict[str, Any] = {'lsm_stack': [], 'apparmor_kernel_enabled': False,
                              'selinux_enforcing': False, 'lsm_observable': False}
    try:
        text = Path('/sys/kernel/security/lsm').read_text(encoding='ascii').strip()
        stack = [x.strip() for x in text.split(',') if x.strip()]
        result['lsm_stack'] = stack
        result['lsm_observable'] = bool(stack)
        if 'apparmor' in stack:
            result['apparmor_kernel_enabled'] = Path('/sys/module/apparmor/parameters/enabled').read_text(encoding='ascii').strip() == 'Y'
        if 'selinux' in stack:
            result['selinux_enforcing'] = Path('/sys/fs/selinux/enforce').read_text(encoding='ascii').strip() == '1'
    except (OSError, UnicodeError):
        pass
    return result


def _observe_unit(role: str, user: str, unit: str, mac: dict[str, Any] | None = None) -> dict[str, Any]:
    report: dict[str, Any] = {'unit': unit, 'user': user, 'verified': False,
                              'checks': {}, 'observations': {}}
    checks = report['checks']
    unit_path = EXPECTED_SYSTEMD_PATH/unit
    checks['root_owned_unit_file'] = _root_owned_protected_file(unit_path)
    try:
        expected_uid = pwd.getpwnam(user).pw_uid
        checks['nonroot_uid'] = expected_uid > 0
        props = _systemd_show(unit)
        checks['expected_systemd_unit'] = props['Id'] == unit
        checks['expected_systemd_user'] = props['User'] == user
        checks['active_service'] = props['ActiveState'] == 'active' and props['SubState'] == 'running'
        checks['unit_fragment_path'] = props['FragmentPath'] == str(unit_path)
        checks['service_invocation_id'] = bool(re.fullmatch(r'[0-9a-f]{32}', props['InvocationID']))
        checks['confined_exec_path'] = props['ExecStart'].startswith('{ path=/opt/cybersec/')
        checks['delegation_worker_only'] = ((props['Delegate'] == 'yes') if role == 'worker'
                                             else (props['Delegate'] == 'no'))
        mode = mac if mac is not None else _mac_enforcement()
        apparmor = mode.get('apparmor_kernel_enabled', False)
        selinux = mode.get('selinux_enforcing', False)
        checks['lsm_unit_profile'] = (bool(props['AppArmorProfile']) and
            'unconfined' not in props['AppArmorProfile'].lower()) if apparmor else bool(selinux)
        pid = int(props['MainPID'])
        if pid <= 1:
            raise ValueError('Invalid live service PID')
        start_a, cgroup, uids, label = _starttime_and_cgroup(pid)
        checks['exact_service_cgroup'] = cgroup == props['ControlGroup'] and cgroup.endswith('/' + unit)
        checks['four_uid_fields'] = uids == (expected_uid,) * 4
        if apparmor:
            checks['enforcing_process_label'] = (label.endswith(' (enforce)')
                and 'unconfined' not in label.lower())
            checks['mac_matches_unit'] = label.split(' (')[0] == props['AppArmorProfile']
        elif selinux:
            # SELinux labels are security contexts, not AppArmor profile names;
            # constrain to an independently-installed role-specific domain.
            expected_domain = 'cybersec_' + role + '_t'
            checks['enforcing_process_label'] = bool(re.fullmatch(
                r'[^:]+:[^:]+:' + expected_domain + r':s[0-9]+(?:-[s0-9]+)?', label))
            checks['mac_matches_unit'] = checks['enforcing_process_label']
        else:
            checks['enforcing_process_label'] = False
            checks['mac_matches_unit'] = False
        start_b, _, _, _ = _starttime_and_cgroup(pid)
        checks['stable_pid_starttime'] = start_a == start_b
        report['observations'] = {'pid': pid, 'starttime': start_a,
                                   'cgroup': cgroup, 'mac_label': label,
                                   'uids': list(uids)}
    except (OSError, KeyError, ValueError, RuntimeError, subprocess.TimeoutExpired) as exc:
        report['error'] = type(exc).__name__
    report['verified'] = bool(checks) and all(checks.values())
    return report


def audit_host() -> dict[str, Any]:
    baseline = stage62_audit()
    lsm = _mac_enforcement()
    roles = {name: _observe_unit(name, user, unit, lsm) for name, (user, unit) in ROLES.items()}
    uids = baseline['role_uids']
    ids_good = (len(set(uids.values())) == len(ROLES) and all(v is not None and v > 0 for v in uids.values()))
    role_observation = all(x['verified'] for x in roles.values())
    checks = {
        'four_separate_nonroot_uids': ids_good,
        'kernel_enforcing_lsm': lsm['lsm_observable'] and (lsm['apparmor_kernel_enabled'] or lsm['selinux_enforcing']),
        'four_live_systemd_services': role_observation,
        'root_protected_lab_key': _root_owned_protected_file(Path('/etc/cybersec/trust/lab_ed25519.pub')),
        'root_protected_recovery_key': _root_owned_protected_file(Path('/etc/cybersec/trust/recovery_ed25519.pub')),
        'external_monotonic_root_attested': False,
        'actual_cgroup_escape_negative_test': False,
        'verified_post_sigkill_systemd_restart': False,
        'independent_mac_policy_legacy_bypass_test': False,
        'independent_recovery_authority_consumption': False,
        'signed_attempt_owner_permission_verified_live': False,
    }
    # Deliberately no code path sets externally unproven enforcement tests true.
    return {
        'schema': 'cybersec.stage63.host-audit.v1',
        'status': 'BLOCKED/NO-GO', 'production_admission': False,
        'checks': checks, 'blocked_on': [k for k, v in checks.items() if not v],
        'lsm': lsm, 'roles': roles, 'previous_audit': baseline,
        'independent_e2e_executed': False,
        'external_scanner_executed': False,
    }


def main() -> int:
    print(json.dumps(audit_host(), sort_keys=True, indent=2, ensure_ascii=False))
    return 3


if __name__ == '__main__':
    sys.exit(main())
