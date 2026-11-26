from concurrent.futures import ThreadPoolExecutor
import threading
import time

import pytest

from cybersec.repository import Repository
from cybersec.scan_worker import run_scan_worker


def make_repo(tmp_path):
    repo = Repository(tmp_path / "stage55.sqlite")
    repo.add_target("https://example.test", authorized=True)
    return repo


def test_concurrent_workers_claim_distinct_jobs(tmp_path):
    repo = make_repo(tmp_path)
    jobs = [repo.create_job("https://example.test", "demo") for _ in range(8)]
    def claim(worker):
        return repo.claim_next_scan_job(worker, lease_seconds=30)
    with ThreadPoolExecutor(max_workers=8) as pool:
        claimed = list(pool.map(claim, [f"worker-{i}" for i in range(8)]))
    ids = [job.id for job in claimed if job]
    assert len(ids) == 8
    assert len(set(ids)) == 8
    assert set(ids) == {job.id for job in jobs}


def test_expired_lease_is_recovered_by_another_worker(tmp_path):
    repo = make_repo(tmp_path)
    job = repo.create_job("https://example.test", "demo")
    first = repo.claim_next_scan_job("worker-a", lease_seconds=5)
    assert first and first.id == job.id
    with __import__("cybersec.db", fromlist=["connect"]).connect(repo.db_path) as db:
        db.execute("UPDATE scan_jobs SET lease_until='2000-01-01T00:00:00.000Z' WHERE id=?", (job.id,))
    recovered = repo.claim_next_scan_job("worker-b", lease_seconds=5)
    assert recovered and recovered.id == job.id
    with __import__("cybersec.db", fromlist=["connect"]).connect(repo.db_path) as db:
        row = db.execute("SELECT lease_owner, attempt_count FROM scan_jobs WHERE id=?", (job.id,)).fetchone()
    assert row["lease_owner"] == "worker-b"
    assert row["attempt_count"] == 2


def test_only_lease_owner_can_finish_claimed_job(tmp_path):
    repo = make_repo(tmp_path)
    job = repo.create_job("https://example.test", "demo")
    repo.claim_next_scan_job("worker-a", lease_seconds=30)
    with pytest.raises(RuntimeError):
        repo.finish_claimed_scan_job(job.id, "worker-b")
    finished = repo.finish_claimed_scan_job(job.id, "worker-a")
    assert finished.status == "completed"


def test_worker_executes_demo_job_and_persists_result(tmp_path):
    repo = make_repo(tmp_path)
    job = repo.create_job("https://example.test", "demo")
    summary = run_scan_worker(repo, worker_id="test-worker", lease_seconds=5,
                              idle_seconds=0.1, max_jobs=1)
    assert summary.claimed == 1
    assert summary.completed == 1
    assert repo.get_job(job.id).status == "completed"


def test_cancel_running_job_sets_request_without_releasing_lease(tmp_path):
    repo = make_repo(tmp_path)
    job = repo.create_job("https://example.test", "demo")
    repo.claim_next_scan_job("worker-a", lease_seconds=30)
    cancelled = repo.cancel_scan_job(job.id)
    assert cancelled.status == "running"
    with __import__("cybersec.db", fromlist=["connect"]).connect(repo.db_path) as db:
        row = db.execute("SELECT cancel_requested_at, lease_owner FROM scan_jobs WHERE id=?", (job.id,)).fetchone()
    assert row["cancel_requested_at"]
    assert row["lease_owner"] == "worker-a"
