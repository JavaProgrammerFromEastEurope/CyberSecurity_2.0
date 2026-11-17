"""POSIX process-group supervision for explicitly authorized external jobs.

No scanner is started by importing this module. A caller must opt into it.
"""
from __future__ import annotations

from dataclasses import dataclass
import os
import signal
import subprocess
import time
from typing import Callable, Sequence


@dataclass(frozen=True)
class ProcessOutcome:
    returncode: int
    stdout: str
    stderr: str
    elapsed_seconds: float


class ProcessCancelled(RuntimeError):
    pass


class ProcessSupervisor:
    def __init__(self, *, grace_seconds: float = 1.0, poll_seconds: float = 0.05):
        if os.name != "posix" or not hasattr(os, "killpg"):
            raise RuntimeError("POSIX process-group supervision unavailable: fail closed")
        if grace_seconds <= 0 or poll_seconds <= 0:
            raise ValueError("grace_seconds and poll_seconds must be positive")
        self.grace_seconds = grace_seconds
        self.poll_seconds = poll_seconds

    @staticmethod
    def _signal_group(process: subprocess.Popen, sig: int) -> None:
        # start_new_session ensures the process is the leader of its own group.
        try:
            os.killpg(process.pid, sig)
        except ProcessLookupError:
            pass

    def run(self, argv: Sequence[str], *, timeout: float,
            cancelled: Callable[[], bool] | None = None,
            cwd: str | None = None) -> ProcessOutcome:
        if not argv or not all(isinstance(x, str) and x for x in argv):
            raise ValueError("argv must be nonempty string arguments")
        if timeout <= 0:
            raise ValueError("timeout must be positive")
        if cancelled is not None and cancelled():
            raise ProcessCancelled("cancelled before process start")
        start = time.monotonic()
        process = subprocess.Popen(list(argv), shell=False, start_new_session=True,
                                   stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                   text=True, cwd=cwd)
        # communicate(timeout) drains pipes and prevents stdout/stderr deadlocks.
        try:
            while True:
                if cancelled is not None and cancelled():
                    raise ProcessCancelled("external process cancellation requested")
                remaining = timeout - (time.monotonic() - start)
                if remaining <= 0:
                    raise subprocess.TimeoutExpired(list(argv), timeout)
                try:
                    stdout, stderr = process.communicate(timeout=min(remaining, self.poll_seconds))
                    return ProcessOutcome(process.returncode, stdout, stderr, time.monotonic() - start)
                except subprocess.TimeoutExpired:
                    continue
        except (ProcessCancelled, subprocess.TimeoutExpired):
            # TERM grants a short exit window, KILL fences remaining group
            # members. Never block indefinitely draining inherited pipes.
            self._stop_group(process, graceful=True)
            raise
        except BaseException:
            self._stop_group(process, graceful=False)
            raise

    def _stop_group(self, process: subprocess.Popen, *, graceful: bool) -> None:
        if graceful:
            self._signal_group(process, signal.SIGTERM)
            try:
                process.communicate(timeout=self.grace_seconds)
            except subprocess.TimeoutExpired:
                pass
        # Signal the whole group even if its leader has already exited: a
        # grandchild may still be running or holding stdout/stderr open.
        self._signal_group(process, signal.SIGKILL)
        try:
            process.communicate(timeout=self.grace_seconds)
        except subprocess.TimeoutExpired:
            # A child that calls setsid() can escape the group, and inherited
            # pipes may stay open. Do not hang forever: close our endpoints and
            # reap the direct child. This is NOT proof of whole-tree cleanup.
            for pipe in (process.stdout, process.stderr):
                if pipe is not None:
                    pipe.close()
            if process.poll() is None:
                process.kill()
            try:
                process.wait(timeout=self.grace_seconds)
            except subprocess.TimeoutExpired as exc:
                raise RuntimeError("Unable to reap supervised process; manual recovery required") from exc
