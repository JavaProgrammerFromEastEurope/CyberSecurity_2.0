"""Durable scanner-job worker (separate from notification delivery workers)."""
from __future__ import annotations

import logging
import threading
import time
from dataclasses import dataclass

from cybersec.repository import Repository
from cybersec.runner import JobRunner

logger = logging.getLogger(__name__)


@dataclass(frozen=True)
class WorkerSummary:
    claimed: int
    completed: int
    failed: int


class _LeaseHeartbeat:
    def __init__(self, repository: Repository, job_id: int, worker_id: str,
                 lease_seconds: int, shutdown_event: threading.Event | None = None):
        self.repository = repository
        self.job_id = job_id
        self.worker_id = worker_id
        self.lease_seconds = lease_seconds
        self.shutdown_event = shutdown_event
        self.stop_event = threading.Event()
        self.lost = threading.Event()
        self.abort_event = threading.Event()
        self.cancelled = threading.Event()
        self.attempt = None
        self.thread = threading.Thread(target=self._run, name=f"scan-lease-{job_id}", daemon=True)

    def _run(self) -> None:
        next_renewal = time.monotonic() + self.lease_seconds / 3
        while not self.stop_event.wait(0.2):
            if self.shutdown_event is not None and self.shutdown_event.is_set():
                self.abort_event.set()
                return
            try:
                state = self.repository.inspect_scan_execution(
                    self.job_id, self.worker_id, self.attempt
                )
                if state == "cancelled":
                    self.cancelled.set()
                    self.abort_event.set()
                    return
                if state != "active":
                    self.lost.set()
                    self.abort_event.set()
                    logger.error("Lost lease for scan job #%s", self.job_id)
                    return
                if time.monotonic() >= next_renewal:
                    if not self.repository.renew_scan_job_lease(
                        self.job_id, self.worker_id, lease_seconds=self.lease_seconds
                    ):
                        self.lost.set()
                        self.abort_event.set()
                        logger.error("Cannot renew lease for scan job #%s", self.job_id)
                        return
                    next_renewal = time.monotonic() + self.lease_seconds / 3
            except Exception:
                self.lost.set()
                self.abort_event.set()
                logger.exception("Could not inspect/renew lease for scan job #%s", self.job_id)
                return

    def __enter__(self):
        with __import__("cybersec.db", fromlist=["connect"]).connect(self.repository.db_path) as db:
            row = db.execute("SELECT attempt_count FROM scan_jobs WHERE id=?", (self.job_id,)).fetchone()
        self.attempt = int(row["attempt_count"]) if row else None
        self.thread.start()
        return self

    def __exit__(self, *_):
        self.stop_event.set()
        self.thread.join(timeout=max(2.0, self.lease_seconds / 3 + 1))
        if self.thread.is_alive():
            from cybersec.process_supervision import ScanExecutionUncertain
            raise ScanExecutionUncertain("Lease observer did not stop; worker must not claim another job")


def run_scan_worker(repository: Repository, *, worker_id: str, lease_seconds: int = 60,
                    idle_seconds: float = 2.0, max_jobs: int = 0, max_attempts: int = 3,
                    stop_event: threading.Event | None = None) -> WorkerSummary:
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
    runner = JobRunner(repository)

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
            with _LeaseHeartbeat(repository, job.id, worker_id, lease_seconds,
                                 shutdown_event=stop_event) as monitor:
                runner.run(job.id, worker_id=worker_id, cancel_event=monitor.abort_event)
            current = repository.get_job(job.id)
            if current and current.status == "completed":
                completed += 1
            else:
                failed += 1
        except Exception:
            failed += 1
            logger.exception("Scan job #%s failed in worker %s", job.id, worker_id)
    return WorkerSummary(claimed=claimed, completed=completed, failed=failed)
