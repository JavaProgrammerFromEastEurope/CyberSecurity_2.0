"""Stage 62: explicit cgroup v2 execution gate for independently confined Linux hosts.

No positive production admission is inferred from this module. In particular,
cooperating processes can move themselves between cgroups when MAC does not
prevent writes to cgroup.procs; an independently provisioned systemd/LSM policy
and external authorization are mandatory production prerequisites.

The child starts as a Python trampoline blocked on an inherited pipe. It cannot
exec the scanner before parent-side cgroup migration and verification.
"""
from __future__ import annotations

import os
import re
import selectors
import signal
import subprocess
import sys
import time
from dataclasses import dataclass
from pathlib import Path
from threading import Event
from typing import Sequence

from cybersec.process_supervision import ScanCancelled, ScanExecutionUncertain, SupervisedResult


class ContainmentBlocked(PermissionError):
    """Mandatory containment preflight failed: do not start a scanner."""


class ContainmentUncertain(ScanExecutionUncertain):
    """A scanner could not be proven stopped inside its assigned cgroup."""


_CGROUP_ROOT = Path('/sys/fs/cgroup')
_SCOPE_NAME = re.compile(r'^scan-[a-zA-Z0-9][a-zA-Z0-9_-]{0,63}$')


def production_mode() -> bool:
    """Development switch only; immutable production enforcement requires OS MAC.

    An attacker capable of starting an unconfined same-UID legacy process can
    bypass an environment flag. A production installer MUST confine all scanner
    entry points at OS level. No standalone admission is granted by this flag.
    """
    return os.environ.get('CYBERSEC_EXECUTION_MODE') == 'production'


def _own_cgroup() -> str:
    text = Path('/proc/self/cgroup').read_text(encoding='ascii')
    matches = [line[3:].strip() for line in text.splitlines() if line.startswith('0::')]
    if len(matches) != 1 or not matches[0].startswith('/'):
        raise ContainmentBlocked('Cannot establish unique cgroup v2 placement')
    return matches[0]


def _process_starttime(pid: int) -> str:
    # pid starttime is the 22nd /proc/PID/stat field; comm is parenthesized and
    # may contain spaces or closing parentheses, so split after the last ')'.
    raw = Path(f'/proc/{pid}/stat').read_text(encoding='ascii')
    return raw[raw.rfind(')') + 2:].split()[19]


def _cgroup_for(pid: int) -> str:
    text = Path(f'/proc/{pid}/cgroup').read_text(encoding='ascii')
    matches = [line[3:].strip() for line in text.splitlines() if line.startswith('0::')]
    if len(matches) != 1:
        raise ContainmentBlocked('Process does not have a unique cgroup v2 membership')
    return matches[0]


def verify_attached_process(pid: int, *, starttime: str, exact_cgroup: str) -> None:
    """Check both PID starttime and exact cgroup before pre-exec release."""
    try:
        if (_process_starttime(pid) != starttime or _cgroup_for(pid) != exact_cgroup
                or _process_starttime(pid) != starttime):
            raise ContainmentBlocked('PID reuse or cgroup escape detected before exec')
    except OSError as exc:
        raise ContainmentBlocked('Cannot inspect still-live scanner trampoline') from exc


def _populated(path: Path) -> bool:
    fields = dict(line.split(maxsplit=1) for line in (path/'cgroup.events').read_text(encoding='ascii').splitlines())
    if fields.get('populated') not in ('0', '1'):
        raise ContainmentUncertain('cgroup.events has no valid populated field')
    return fields['populated'] == '1'


@dataclass(frozen=True)
class HostPreflight:
    status: str
    checks: dict[str, bool]
    blockers: tuple[str, ...]
    production_admission: bool = False


def readonly_host_preflight(*, delegated: Path | None = None) -> HostPreflight:
    """Observe the *real* host, never generate approvals or test-only positives."""
    try:
        path = delegated if delegated is not None else _CGROUP_ROOT / _own_cgroup().lstrip('/')
    except (OSError, ContainmentBlocked):
        path = _CGROUP_ROOT / '__not_delegated__' 
    checks: dict[str, bool] = {}
    checks['linux'] = sys.platform == 'linux'
    try:
        checks['systemd_pid1'] = Path('/proc/1/comm').read_text().strip() == 'systemd'
    except OSError:
        checks['systemd_pid1'] = False
    checks['systemd_runtime'] = Path('/run/systemd/system').is_dir()
    try:
        checks['cgroup2_mount'] = any(
            ' - cgroup2 ' in line and ' /sys/fs/cgroup ' in line
            for line in Path('/proc/self/mountinfo').read_text().splitlines())
    except OSError:
        checks['cgroup2_mount'] = False
    checks['delegated_cgroup_directory'] = path.is_dir() and not path.is_symlink()
    checks['delegated_cgroup_writable'] = (path/'cgroup.procs').is_file() and os.access(path/'cgroup.procs', os.W_OK) and os.access(path, os.W_OK)
    checks['cgroup_kill'] = (path/'cgroup.kill').is_file() and os.access(path/'cgroup.kill', os.W_OK)
    try:
        checks['same_cgroup_as_delegation'] = path.resolve() == (_CGROUP_ROOT / _own_cgroup().lstrip('/')).resolve()
    except (OSError, ContainmentBlocked):
        checks['same_cgroup_as_delegation'] = False
    try:
        profile = Path('/proc/self/attr/current').read_text().strip()
        checks['enforcing_mac_profile'] = bool(profile and 'unconfined' not in profile.lower() and '(enforce)' in profile.lower())
    except OSError:
        checks['enforcing_mac_profile'] = False
    # A positive host observation is never a production permit: cgroup migration
    # prohibition, multi-UID separation and signed lab authorization still need
    # evidence from independent principals and real restart/kill tests.
    return HostPreflight('BLOCKED/NO-GO', checks, tuple(key for key,value in checks.items() if not value))


@dataclass(frozen=True)
class CgroupV2Executor:
    """Only usable in a writable, independently delegated cgroup v2 subtree."""
    delegated_path: Path

    def _preflight(self) -> tuple[Path, str]:
        path = self.delegated_path
        if sys.platform != 'linux' or path.is_symlink() or not path.is_dir():
            raise ContainmentBlocked('Linux delegated cgroup v2 directory required')
        try:
            root = _CGROUP_ROOT.resolve(strict=True)
            real = path.resolve(strict=True)
            if real == root or not real.is_relative_to(root):
                raise ContainmentBlocked('Cannot use root or external cgroup')
            relative = '/' + str(real.relative_to(root))
            if _own_cgroup() != relative:
                raise ContainmentBlocked('Runner is not itself inside delegated cgroup')
            if not all((path/n).is_file() for n in ('cgroup.procs', 'cgroup.events', 'cgroup.kill')):
                raise ContainmentBlocked('Kernel cgroup v2 controls unavailable')
            if not (os.access(path, os.W_OK) and os.access(path/'cgroup.procs', os.W_OK)
                    and os.access(path/'cgroup.kill', os.W_OK)):
                raise ContainmentBlocked('Writable cgroup delegation/cgroup.kill unavailable')
            if not Path('/run/systemd/system').is_dir() or Path('/proc/1/comm').read_text().strip() != 'systemd':
                raise ContainmentBlocked('Independent systemd service manager unavailable')
            if not relative.endswith('/cybersec-scanner-worker.service') or not os.environ.get('INVOCATION_ID'):
                raise ContainmentBlocked('Scanner is not in the expected systemd-managed service')
            if not hasattr(os, 'pidfd_open') or not hasattr(signal, 'pidfd_send_signal'):
                raise ContainmentBlocked('Kernel pidfd signal authority unavailable')
            # Enforcing AppArmor of this runner is not proof of confinement for
            # descendants; a separate audited production admission remains mandatory.
            label = Path('/proc/self/attr/current').read_text().strip()
            if not label or '(enforce)' not in label or 'unconfined' in label.lower():
                raise ContainmentBlocked('Enforcing MAC/LSM service profile unavailable')
            return real, relative
        except (FileNotFoundError, PermissionError, OSError) as exc:
            raise ContainmentBlocked('Cannot establish independent cgroup admission') from exc

    def run(self, args: Sequence[str], *, timeout: float, cancel_event: Event | None = None,
            poll_seconds: float = 0.1, term_grace_seconds: float = 0.5,
            max_output_bytes: int = 1_048_576) -> SupervisedResult:
        if not args or not all(isinstance(a,str) and a and '\x00' not in a for a in args):
            raise ValueError('args must contain nonempty NUL-free strings')
        if not 0 < timeout <= 1800 or not 0.01 <= poll_seconds <= 1:
            raise ValueError('Invalid timeout or polling interval')
        if not 0.05 <= term_grace_seconds <= 30 or not 1024 <= max_output_bytes <= 4_194_304:
            raise ValueError('Invalid escalation or output bound')
        if cancel_event is not None and cancel_event.is_set():
            raise ScanCancelled('Cancelled before cgroup allocation')
        parent, relative = self._preflight()  # MUST run before any subprocess
        import secrets
        child_name = 'scan-' + secrets.token_hex(12)
        if not _SCOPE_NAME.fullmatch(child_name):
            raise ContainmentBlocked('Invalid generated scope name')
        child = parent/child_name
        child.mkdir(mode=0o700)  # delegated parent, not a forged fixture
        proc: subprocess.Popen | None = None
        pidfd: int | None = None
        gate_read = gate_write = None
        selector = selectors.DefaultSelector()
        termination_reason = None
        try:
            # cgroup.kill must be present on the *fresh* child before launch.
            if not (child/'cgroup.kill').is_file() or not os.access(child/'cgroup.kill', os.W_OK):
                raise ContainmentBlocked('Cannot use kernel cgroup.kill for child scope')
            if _populated(child):
                raise ContainmentBlocked('New scan cgroup is not empty')
            gate_read, gate_write = os.pipe()
            command = [sys.executable, '-m', 'cybersec.cgroup_trampoline',
                       '--gate-fd', str(gate_read), '--expected-cgroup', relative+'/'+child_name,
                       '--', *args]
            proc = subprocess.Popen(command, shell=False, start_new_session=True,
                                    stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                    close_fds=True, pass_fds=(gate_read,))
            os.close(gate_read)
            gate_read = None
            # Keep a kernel reference to this process; never signal a numeric
            # PGID which may have been recycled after the leader was reaped.
            pidfd = os.pidfd_open(proc.pid, 0)
            observed_starttime = _process_starttime(proc.pid)
            # Attach a suspended (not yet exec'd) child to the dedicated cgroup.
            (child/'cgroup.procs').write_text(str(proc.pid)+'\n', encoding='ascii')
            verify_attached_process(proc.pid, starttime=observed_starttime,
                                    exact_cgroup=relative+'/'+child_name)
            os.write(gate_write, b'1')  # exec permission only after membership proof
            os.close(gate_write)
            gate_write = None
            assert proc.stdout is not None and proc.stderr is not None
            output = {'stdout':bytearray(), 'stderr':bytearray()}
            truncated = {'stdout':False,'stderr':False}
            for name, stream in (('stdout',proc.stdout),('stderr',proc.stderr)):
                os.set_blocking(stream.fileno(),False)
                selector.register(stream, selectors.EVENT_READ, data=name)
            deadline = time.monotonic()+timeout
            terminated_at = 0.0
            escalation_sent = False
            while True:
                now = time.monotonic()
                if not termination_reason and (cancel_event is not None and cancel_event.is_set() or now >= deadline):
                    termination_reason = 'cancelled' if cancel_event is not None and cancel_event.is_set() else 'timeout'
                    terminated_at = now
                    try:
                        signal.pidfd_send_signal(pidfd, signal.SIGTERM)
                    except ProcessLookupError:
                        pass
                    # Descendants which fork/setsid survive graceful TERM;
                    # kernel cgroup.kill is the mandatory final fence.
                if termination_reason and not escalation_sent and now-terminated_at >= term_grace_seconds:
                    (child/'cgroup.kill').write_text('1',encoding='ascii')
                    escalation_sent = True
                for key,_ in selector.select(timeout=poll_seconds):
                    try:
                        data = os.read(key.fileobj.fileno(), 65536)
                    except BlockingIOError:
                        continue
                    if not data:
                        selector.unregister(key.fileobj)
                        continue
                    name = key.data
                    room = max_output_bytes-len(output[name])
                    if room:
                        output[name].extend(data[:room])
                    if len(data)>room:
                        truncated[name]=True
                if proc.poll() is not None and not selector.get_map():
                    proc.wait()  # Reap leader before evaluating cgroup population.
                    # Even detached, stdio-closed children remain visible via
                    # cgroup.events populated; reject success and kill survivors.
                    if _populated(child):
                        raise ContainmentUncertain('Scanner left descendants in its cgroup')
                    if termination_reason is None or escalation_sent:
                        break
                if termination_reason and escalation_sent and now-terminated_at > term_grace_seconds+3:
                    raise ContainmentUncertain('Scanner cgroup did not drain after SIGKILL')
            if termination_reason == 'cancelled':
                raise ScanCancelled('Scanner cancelled; kernel cgroup.kill verified')
            if termination_reason == 'timeout':
                raise TimeoutError('Scanner exceeded supervised cgroup timeout')
            return SupervisedResult(tuple(args),proc.returncode,
                    output['stdout'].decode('utf-8',errors='replace'),
                    output['stderr'].decode('utf-8',errors='replace'),
                    truncated['stdout'],truncated['stderr'])
        finally:
            if gate_read is not None:
                os.close(gate_read)
            if gate_write is not None:
                os.close(gate_write)  # EOF causes trampoline to abort before exec
            selector.close()
            if pidfd is not None:
                os.close(pidfd)
            # Always kill the *cgroup*, not a possibly recycled numeric PID.
            kill_error=None
            try:
                (child/'cgroup.kill').write_text('1',encoding='ascii')
            except OSError as exc:
                kill_error=exc
            if proc is not None:
                try:
                    proc.wait(timeout=3)
                except subprocess.TimeoutExpired:
                    pass
                if proc.stdout is not None:
                    proc.stdout.close()
                if proc.stderr is not None:
                    proc.stderr.close()
            drained=False
            for _ in range(50):
                try:
                    if not _populated(child):
                        drained=True
                        break
                except (OSError, ContainmentUncertain):
                    pass
                time.sleep(0.02)
            if drained:
                try:
                    child.rmdir()
                except OSError as exc:
                    raise ContainmentUncertain('Cannot remove scan cgroup after termination') from exc
            if kill_error is not None or not drained:
                raise ContainmentUncertain('Cannot prove kernel cgroup.kill drained scanner') from kill_error
