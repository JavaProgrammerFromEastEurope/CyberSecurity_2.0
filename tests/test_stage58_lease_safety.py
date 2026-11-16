"""Cancellation and stale-owner safety regression tests."""
import pytest
from cybersec.repository import Repository
from cybersec.db import connect


def setup(tmp_path):
    repo = Repository(tmp_path / "stage58.db")
    repo.add_target("https://example.test", authorized=True)
    job = repo.create_job("https://example.test", "demo")
    repo.claim_next_scan_job("owner-a", lease_seconds=5)
    return repo, job


def expire(repo, job):
    with connect(repo.db_path) as db:
        db.execute("UPDATE scan_jobs SET lease_until='2000-01-01T00:00:00.000Z' WHERE id=?", (job.id,))


def test_cancelled_running_job_can_renew_lease_to_finish_safely(tmp_path):
    repo, job = setup(tmp_path)
    repo.cancel_scan_job(job.id)
    assert repo.renew_scan_job_lease(job.id, "owner-a", lease_seconds=5)
    assert repo.claim_next_scan_job("owner-b", lease_seconds=5) is None
    assert repo.finish_claimed_scan_job(job.id, "owner-a").status == "cancelled"


def test_cancelled_expired_job_is_terminal_not_reclaimed(tmp_path):
    repo, job = setup(tmp_path)
    repo.cancel_scan_job(job.id)
    expire(repo, job)
    assert repo.claim_next_scan_job("owner-b", lease_seconds=5) is None
    assert repo.get_job(job.id).status == "cancelled"


def test_expired_owner_cannot_renew_or_finish(tmp_path):
    repo, job = setup(tmp_path)
    expire(repo, job)
    assert not repo.renew_scan_job_lease(job.id, "owner-a", lease_seconds=5)
    with pytest.raises(RuntimeError):
        repo.finish_claimed_scan_job(job.id, "owner-a")


def test_expired_owner_cannot_publish_artifacts(tmp_path):
    repo, job = setup(tmp_path)
    expire(repo, job)
    with pytest.raises(RuntimeError):
        repo.assert_active_scan_lease(job.id, "owner-a")


def test_new_owner_fences_previous_owner(tmp_path):
    repo, job = setup(tmp_path)
    expire(repo, job)
    assert repo.claim_next_scan_job("owner-b", lease_seconds=5).id == job.id
    with pytest.raises(RuntimeError):
        repo.assert_active_scan_lease(job.id, "owner-a")
    repo.assert_active_scan_lease(job.id, "owner-b")
