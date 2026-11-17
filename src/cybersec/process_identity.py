"""Kernel-backed read-only process identity observations for supervisor audits.

A PID is not a stable identity. PID + /proc stat starttime + cgroup together
are observational evidence; this module does not grant kill or exec authority.
"""
from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
import re


@dataclass(frozen=True)
class ProcessIdentity:
    pid: int
    start_ticks: int
    cgroup: str


def parse_start_ticks(proc_stat: str) -> int:
    """Field 22 of /proc/PID/stat, with arbitrary ')' in field 2 comm."""
    index = proc_stat.rfind(')')
    if index < 0 or not re.match(r'^\d+ \(', proc_stat):
        raise ValueError('Malformed /proc stat entry')
    values = proc_stat[index + 2:].split()
    if len(values) < 20:
        raise ValueError('Missing process start ticks')
    ticks = int(values[19])
    if ticks < 0:
        raise ValueError('Negative start ticks')
    return ticks


def parse_cgroup(proc_cgroup: str) -> str:
    matches = [line[3:] for line in proc_cgroup.splitlines() if line.startswith('0::')]
    if len(matches) != 1 or not matches[0].startswith('/') or '..' in matches[0].split('/'):
        raise ValueError('Missing or ambiguous cgroup v2 membership')
    return matches[0]


def observe_process(pid: int, *, proc_root: Path = Path('/proc')) -> ProcessIdentity:
    """Double-check start ticks across cgroup observation to detect PID reuse."""
    if type(pid) is not int or pid <= 1:
        raise ValueError('Must observe a live non-init process')
    base = proc_root / str(pid)
    first = parse_start_ticks((base / 'stat').read_text(encoding='ascii'))
    group = parse_cgroup((base / 'cgroup').read_text(encoding='ascii'))
    second = parse_start_ticks((base / 'stat').read_text(encoding='ascii'))
    if first != second:
        raise RuntimeError('PID changed identity during observation')
    return ProcessIdentity(pid=pid, start_ticks=first, cgroup=group)


def matches_identity(expected: ProcessIdentity, *, proc_root: Path = Path('/proc')) -> bool:
    try:
        return observe_process(expected.pid, proc_root=proc_root) == expected
    except (OSError, ValueError, RuntimeError):
        return False


def read_population(cgroup: Path) -> bool | None:
    """Read cgroup v2 events. None means the kernel evidence is unavailable."""
    try:
        if cgroup.is_symlink():
            return None
        values = dict(line.split(None, 1) for line in (cgroup / 'cgroup.events').read_text().splitlines()
                      if len(line.split(None, 1)) == 2)
    except (OSError, ValueError):
        return None
    if values.get('populated') == '0':
        return False
    if values.get('populated') == '1':
        return True
    return None
