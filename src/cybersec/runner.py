"""Job execution coordinator for registered scanner adapters."""
from __future__ import annotations

from cybersec.repository import Repository
from cybersec.scanners import AdapterRegistry, ScanContext, ScanResult, default_registry


class JobRunner:
    def __init__(self, repository: Repository, registry: AdapterRegistry | None = None):
        self.repository = repository
        self.registry = registry or default_registry()

    def run(self, job_id: int, *, worker_id: str | None = None,
            cancel_event=None) -> ScanResult:
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

        # Neither direct legacy API nor unconfined worker modes can open
        # production external scanners. OS MAC must separately fence bypasses.
        from cybersec.cgroup_containment import production_mode, ContainmentBlocked
        if production_mode() and job.tool in ('nuclei','zap','sqlmap'):
            if worker_id is None:
                raise ContainmentBlocked('Direct legacy scanner production API is prohibited')
            if job.tool != 'nuclei':
                raise ContainmentBlocked('Only isolated authorized-lab Nuclei is a Stage 62 candidate')
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
                self.repository.finish_claimed_scan_job(
                    job_id, worker_id, error="Cancellation requested before scanner start.", attempt=claimed_attempt,
                )
                raise RuntimeError(f"Scan job #{job_id} was cancelled before scanner start.")
        try:
            if cancel_event is not None and cancel_event.is_set():
                from cybersec.process_supervision import ScanCancelled
                raise ScanCancelled("Worker cancelled before adapter execution")
            result = adapter.run(ScanContext(
                job_id=job.id, target_url=target.url, tool=job.tool,
                options={"cancel_event": cancel_event, "worker_id": worker_id,
                         "attempt": claimed_attempt} if worker_id is not None else {},
            ))
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
                    error = f"{type(exc).__name__}: {exc}"
                    if isinstance(exc, __import__("cybersec.process_supervision", fromlist=["ScanCancelled"]).ScanCancelled):
                        error += " (manual recovery required if remote effects are uncertain)"
                    self.repository.finish_claimed_scan_job(
                        job_id, worker_id, error=error, attempt=claimed_attempt,
                    )
                except RuntimeError:
                    pass
            else:
                self.repository.finish_job(job_id, error=f"{type(exc).__name__}: {exc}")
            raise
