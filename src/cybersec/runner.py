"""Job execution coordinator for registered scanner adapters."""
from __future__ import annotations

from cybersec.repository import Repository
from cybersec.scanners import AdapterRegistry, ScanContext, ScanResult, default_registry


class JobRunner:
    def __init__(self, repository: Repository, registry: AdapterRegistry | None = None):
        self.repository = repository
        self.registry = registry or default_registry()

    def run(self, job_id: int, *, worker_id: str | None = None) -> ScanResult:
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
            with __import__("cybersec.db", fromlist=["connect"]).connect(self.repository.db_path) as db:
                lease = db.execute("SELECT lease_owner, cancel_requested_at, attempt_count, lease_until FROM scan_jobs WHERE id=?", (job_id,)).fetchone()
            if lease is None or lease["lease_owner"] != worker_id:
                raise RuntimeError(f"Worker {worker_id!r} does not own scan job #{job_id}.")
            self.repository.assert_active_scan_lease(job_id, worker_id)
            claimed_attempt = int(lease["attempt_count"])
            if lease["cancel_requested_at"]:
                self.repository.finish_claimed_scan_job(job_id, worker_id, error="Cancellation requested before scanner start.")
                raise RuntimeError(f"Scan job #{job_id} was cancelled before scanner start.")
        try:
            result = adapter.run(ScanContext(job_id=job.id, target_url=target.url, tool=job.tool))
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
                try:
                    self.repository.finish_claimed_scan_job(job_id, worker_id, error=f"{type(exc).__name__}: {exc}")
                except RuntimeError:
                    pass
            else:
                self.repository.finish_job(job_id, error=f"{type(exc).__name__}: {exc}")
            raise
