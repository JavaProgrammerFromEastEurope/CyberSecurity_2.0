"""Durable scanner-job worker (separate from notification delivery workers)."""
from __future__ import annotations

import logging
import signal
from contextlib import contextmanager
import threading
import time
from dataclasses import dataclass

from cybersec.repository import Repository
from cybersec.runner import JobRunner
from cybersec.scanners import AdapterRegistry

logger = logging.getLogger(__name__)


@contextmanager
def worker_signal_handlers(stop_event: threading.Event):
    """Main-thread CLI SIGTERM/SIGINT requests cooperative subprocess stop.

    SIGKILL cannot be intercepted. Always restore existing handlers so the
    library API remains usable by long-running hosts.
    """
    if threading.current_thread() is not threading.main_thread():
        raise RuntimeError("Signal handlers may only be installed in the main thread")
    previous = {sig: signal.getsignal(sig) for sig in (signal.SIGINT, signal.SIGTERM)}
    try:
        for sig in previous:
            signal.signal(sig, lambda signum, frame: stop_event.set())
        yield
    finally:
        for sig, handler in previous.items():
            signal.signal(sig, handler)


@dataclass(frozen=True)
class WorkerSummary:
    claimed: int
    completed: int
    failed: int


class _LeaseHeartbeat:
    def __init__(self, repository: Repository, job_id: int, worker_id: str, lease_seconds: int):
        self.repository = repository
        self.job_id = job_id
        self.worker_id = worker_id
        self.lease_seconds = lease_seconds
        self.stop_event = threading.Event()
        self.lost = threading.Event()
        self.thread = threading.Thread(target=self._run, name=f"scan-lease-{job_id}", daemon=True)

    def _run(self) -> None:
        interval = max(1.0, self.lease_seconds / 3)
        while not self.stop_event.wait(interval):
            try:
                if not self.repository.renew_scan_job_lease(
                    self.job_id, self.worker_id, lease_seconds=self.lease_seconds
                ):
                    self.lost.set()
                    logger.error("Lost lease for scan job #%s", self.job_id)
                    return
            except Exception:
                self.lost.set()
                logger.exception("Could not renew lease for scan job #%s", self.job_id)
                return

    def __enter__(self):
        self.thread.start()
        return self

    def __exit__(self, *_):
        self.stop_event.set()
        self.thread.join(timeout=max(2.0, self.lease_seconds / 3 + 1))


def run_scan_worker(repository: Repository, *, worker_id: str, lease_seconds: int = 60,
                    idle_seconds: float = 2.0, max_jobs: int = 0, max_attempts: int = 3,
                    stop_event: threading.Event | None = None,
                    registry: AdapterRegistry | None = None) -> WorkerSummary:
    from cybersec.production_admission import require_production_admission
    require_production_admission(action="scanner-worker lifecycle")
    worker_id = str(worker_id).strip()
    if not worker_id or len(worker_id) > 128:
        raise ValueError("worker_id must contain 1-128 characters.")
    if not 5 <= lease_seconds <= 3600:
        raise ValueError("lease_seconds must be between 5 and 3600.")
    if not 0.1 <= idle_seconds <= 60:
        raise ValueError("idle_seconds must be between 0.1 and 60.")
    if max_jobs < 0:
        raise ValueError("max_jobs cannot be negative.")
    stop_event = stop_event or threading.Event()
    claimed = completed = failed = 0
    runner = JobRunner(repository, registry=registry)

    while not stop_event.is_set() and (max_jobs == 0 or claimed < max_jobs):
        job = repository.claim_next_scan_job(
            worker_id, lease_seconds=lease_seconds, max_attempts=max_attempts
        )
        if job is None:
            if max_jobs and claimed >= max_jobs:
                break
            stop_event.wait(idle_seconds)
            continue
        claimed += 1
        try:
            with _LeaseHeartbeat(repository, job.id, worker_id, lease_seconds) as heartbeat:
                runner.run(job.id, worker_id=worker_id,
                           stop_requested=lambda: stop_event.is_set() or heartbeat.lost.is_set())
            current = repository.get_job(job.id)
            if current and current.status == "completed":
                completed += 1
            else:
                failed += 1
        except Exception:
            failed += 1
            logger.exception("Scan job #%s failed in worker %s", job.id, worker_id)
    return WorkerSummary(claimed=claimed, completed=completed, failed=failed)
