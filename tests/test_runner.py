import pytest

from cybersec.repository import Repository
from cybersec.runner import JobRunner
from cybersec.scanners import AdapterRegistry, ScanContext, ScanResult


def _repo(tmp_path, tool="demo"):
    repo = Repository(tmp_path / "test.db")
    repo.add_target("https://example.com", authorized=True)
    job = repo.create_job("https://example.com", tool)
    return repo, job


def test_demo_runner_completes_without_network_access(tmp_path):
    repo, job = _repo(tmp_path)
    result = JobRunner(repo).run(job.id)
    updated = repo.get_job(job.id)
    assert result.status == "completed"
    assert result.raw_output["network_requests"] == 0
    assert updated.status == "completed"
    assert updated.started_at is not None
    assert updated.finished_at is not None


def test_unsupported_adapter_does_not_start_job(tmp_path):
    repo, job = _repo(tmp_path, "sqlmap")
    with pytest.raises(LookupError, match="No executable adapter registered"):
        JobRunner(repo).run(job.id)
    assert repo.get_job(job.id).status == "queued"


def test_job_cannot_run_twice(tmp_path):
    repo, job = _repo(tmp_path)
    runner = JobRunner(repo)
    runner.run(job.id)
    with pytest.raises(ValueError, match="Only queued jobs can run"):
        runner.run(job.id)


def test_adapter_failure_marks_job_failed(tmp_path):
    repo, job = _repo(tmp_path)
    class BrokenAdapter:
        name = "demo"
        def run(self, context: ScanContext) -> ScanResult:
            raise RuntimeError("simulated adapter failure")

    registry = AdapterRegistry()
    registry.register(BrokenAdapter())
    with pytest.raises(RuntimeError, match="simulated adapter failure"):
        JobRunner(repo, registry).run(job.id)
    updated = repo.get_job(job.id)
    assert updated.status == "failed"
    assert "simulated adapter failure" in updated.error


def test_cancel_only_queued_jobs(tmp_path):
    repo, job = _repo(tmp_path)
    cancelled = repo.cancel_job(job.id)
    assert cancelled.status == "cancelled"
    with pytest.raises(ValueError, match="Only queued jobs can be cancelled"):
        repo.cancel_job(job.id)
