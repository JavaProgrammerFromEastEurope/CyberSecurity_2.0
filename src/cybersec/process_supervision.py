"""Stage 61: bounded POSIX process-group supervision for worker-owned scanners.

This is a local process control layer, NOT OS-enforced containment. A descendant
which creates a new session, loses inherited FDs, or survives host shutdown is
outside this contract; a writable delegated cgroup/systemd service is required
for externally verified production confinement.
"""
from __future__ import annotations

import os
import selectors
import signal
import subprocess
import time
from dataclasses import dataclass
from threading import Event
from typing import Sequence


class ScanCancelled(RuntimeError):
    """A cancellation signal stopped the supervised local scanner invocation."""


class ScanExecutionUncertain(RuntimeError):
    """Local process-tree termination could not be established; never auto-retry."""


@dataclass(frozen=True)
class SupervisedResult:
    args: tuple[str, ...]
    returncode: int
    stdout: str
    stderr: str
    stdout_truncated: bool
    stderr_truncated: bool


def run_supervised(
    args: Sequence[str], *, timeout: float, cancel_event: Event | None = None,
    poll_seconds: float = 0.1, term_grace_seconds: float = 0.5,
    max_output_bytes: int = 1_048_576,
) -> SupervisedResult:
    """Run without a shell, bounded output, timeout and SIGTERM->SIGKILL escalation.

    No remote scanner daemon is signalled, and external side effects are not
    rolled back. One invocation never retries implicitly.
    """
    if os.name != "posix" or not hasattr(os, "killpg"):
        raise ScanExecutionUncertain("POSIX process group support unavailable")
    if not args or not all(isinstance(a, str) and a and "\x00" not in a for a in args):
        raise ValueError("args must contain nonempty NUL-free strings")
    if not 0 < timeout <= 1800 or not 0.01 <= poll_seconds <= 1:
        raise ValueError("invalid timeout or polling interval")
    if not 0.05 <= term_grace_seconds <= 30 or not 1024 <= max_output_bytes <= 4_194_304:
        raise ValueError("invalid escalation or output bound")
    if cancel_event is not None and cancel_event.is_set():
        raise ScanCancelled("Scan cancelled before subprocess launch")

    proc = subprocess.Popen(list(args), shell=False, start_new_session=True, close_fds=True,
                            stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    selected = selectors.DefaultSelector()
    out: dict[str, bytearray] = {"stdout": bytearray(), "stderr": bytearray()}
    trunc = {"stdout": False, "stderr": False}
    deadline = time.monotonic() + timeout
    termination_reason: str | None = None
    termination_started: float | None = None
    escalation_sent = False
    try:
        assert proc.stdout is not None and proc.stderr is not None
        for name, file in (("stdout", proc.stdout), ("stderr", proc.stderr)):
            os.set_blocking(file.fileno(), False)
            selected.register(file, selectors.EVENT_READ, data=name)
        while True:
            now = time.monotonic()
            if termination_reason is None:
                if cancel_event is not None and cancel_event.is_set():
                    termination_reason = "cancelled"
                elif now >= deadline:
                    termination_reason = "timeout"
                if termination_reason:
                    termination_started = now
                    try:
                        os.killpg(proc.pid, signal.SIGTERM)
                    except ProcessLookupError:
                        pass
                    except OSError as exc:
                        raise ScanExecutionUncertain("Could not signal scanner process group") from exc
            elif not escalation_sent and now - termination_started >= term_grace_seconds:
                # The group may contain children after the leader has exited.
                try:
                    os.killpg(proc.pid, signal.SIGKILL)
                except ProcessLookupError:
                    pass
                except OSError as exc:
                    raise ScanExecutionUncertain("Could not kill scanner process group") from exc
                escalation_sent = True

            for key, _ in selected.select(timeout=poll_seconds):
                fd = key.fileobj
                try:
                    data = os.read(fd.fileno(), 65536)
                except BlockingIOError:
                    continue
                if not data:
                    selected.unregister(fd)
                    continue
                name = key.data
                remaining = max_output_bytes - len(out[name])
                if remaining:
                    out[name].extend(data[:remaining])
                if len(data) > remaining:
                    trunc[name] = True
            # Do not return on an early leader exit until the escalation phase
            # has signalled its original process group. The leader may have
            # forked children which survived SIGTERM.
            if proc.poll() is not None and not selected.get_map() and (
                termination_reason is None or escalation_sent
            ):
                break
            # A descendant can keep pipes open after the leader is reaped. Always
            # escalate and refuse to hang indefinitely on unbounded descendants.
            if termination_reason is not None and escalation_sent and now - termination_started > term_grace_seconds + 3:
                raise ScanExecutionUncertain("Scanner process group did not close all inherited pipes")
        if termination_reason == "cancelled":
            raise ScanCancelled("Scanner cancelled; local process-group stop requested")
        if termination_reason == "timeout":
            raise TimeoutError("Scanner exceeded bounded execution timeout")
        return SupervisedResult(tuple(args), proc.returncode,
                                out["stdout"].decode("utf-8", errors="replace"),
                                out["stderr"].decode("utf-8", errors="replace"),
                                trunc["stdout"], trunc["stderr"])
    finally:
        if proc.poll() is None:
            try:
                os.killpg(proc.pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
            except OSError:
                pass
            try:
                proc.wait(timeout=3)
            except subprocess.TimeoutExpired:
                pass
        selected.close()
        if proc.stdout is not None:
            proc.stdout.close()
        if proc.stderr is not None:
            proc.stderr.close()
