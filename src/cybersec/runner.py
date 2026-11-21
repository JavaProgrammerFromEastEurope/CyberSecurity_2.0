"""Job execution coordinator for registered scanner adapters."""
from __future__ import annotations

from typing import Callable

from cybersec.db import connect
from cybersec.process_supervisor import ProcessCancelled
from cybersec.repository import Repository
from cybersec.scanners import AdapterRegistry, ScanContext, ScanResult, default_registry


class JobRunner:
    def __init__(self, repository: Repository, registry: AdapterRegistry | None = None):
        self.repository = repository
        self.registry = registry or default_registry()

    def run(self, job_id: int, *, worker_id: str | None = None,
            stop_requested: Callable[[], bool] | None = None) -> ScanResult:
        from cybersec.production_admission import require_production_admission
        require_production_admission(action="JobRunner.run")
        job = self.repository.get_job(job_id)
        if job is None:
            raise ValueError(f"Job #{job_id} does not exist.")
        if worker_id is None and job.status != "queued":
            raise ValueError(f"Only queued jobs can run; job #{job_id} is '{job.status}'.")
        if worker_id is not None and job.status != "running":
            raise ValueError(f"Worker-owned job #{job_id} is not running (status={job.status}).")

        target = self.repository.get_target_by_id(job.target_id)
        if target is None:
            raise ValueError(f"Target for job #{job_id} no longer exists.")
        if not target.authorized:
            raise PermissionError("Target authorization acknowledgement is missing; refusing to run job.")

        # Resolve adapter before changing the job state, so unsupported tools remain queued.
        adapter = self.registry.get(job.tool)
        if worker_id is None:
            self.repository.start_job(job_id)
        else:
            with connect(self.repository.db_path) as db:
                lease = db.execute("SELECT lease_owner, cancel_requested_at, attempt_count, lease_until FROM scan_jobs WHERE id=?", (job_id,)).fetchone()
            if lease is None or lease["lease_owner"] != worker_id:
                raise RuntimeError(f"Worker {worker_id!r} does not own scan job #{job_id}.")
            self.repository.assert_active_scan_lease(job_id, worker_id)
            claimed_attempt = int(lease["attempt_count"])
            if lease["cancel_requested_at"]:
                self.repository.finish_claimed_scan_job(job_id, worker_id, error="Cancellation requested before scanner start.")
                raise RuntimeError(f"Scan job #{job_id} was cancelled before scanner start.")
        try:
            if worker_id is not None:
                def interrupted() -> bool:
                    return (bool(stop_requested and stop_requested()) or
                            self.repository.scan_job_execution_interrupted(job.id, worker_id, claimed_attempt))
                if interrupted():
                    raise ProcessCancelled("worker execution cancelled or lease lost before adapter start")
                # Private in-memory callback; never serialized into the stored artifact.
                options = {"_worker_interrupted": interrupted}
            else:
                options = {}
            result = adapter.run(ScanContext(job_id=job.id, target_url=target.url,
                                             tool=job.tool, options=options))
            if worker_id is not None and interrupted():
                raise ProcessCancelled("worker execution cancelled or lease lost before result commit")
            artifact_payload = {
                "summary": result.summary,
                "raw_output": result.raw_output,
                "findings": list(result.findings),
            }
            if worker_id is not None:
                # The worker must capture its token before adapter execution (see below).
                self.repository.commit_claimed_scan_result(
                    job.id, worker_id, claimed_attempt, result.tool, artifact_payload,
                    adapter_status=result.status if result.status in {"completed", "failed", "partial"} else "failed",
                    summary=result.summary, finding_count=len(result.findings),
                )
            else:
                self.repository.store_scan_artifact(
                    job.id, result.tool, artifact_payload,
                    status="complete" if result.status == "completed" else "partial",
                    metadata={"adapter_status": result.status, "finding_count": len(result.findings)},
                )
                if result.status == "completed":
                    self.repository.finish_job(job_id)
                else:
                    self.repository.finish_job(job_id, error=result.summary or f"Adapter returned status '{result.status}'.")
            return result
        except Exception as exc:
            if worker_id is not None:
                # A non-cancelled external job stopped by service shutdown may
                # already have had side effects: recovery must be operator gated.
                error = ("External scanner interrupted; manual recovery required "
                         "(execution state unknown)." if isinstance(exc, ProcessCancelled)
                         and job.tool != "demo" else f"{type(exc).__name__}: {exc}")
                try:
                    self.repository.finish_claimed_scan_job(job_id, worker_id, error=error)
                except RuntimeError:
                    # Lease expired or transferred: never overwrite newer state.
                    pass
            else:
                self.repository.finish_job(job_id, error=f"{type(exc).__name__}: {exc}")
            raise
