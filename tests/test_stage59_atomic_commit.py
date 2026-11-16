import pytest
from cybersec.repository import Repository


def setup(tmp_path):
    repo = Repository(tmp_path / 'scan.sqlite')
    target = repo.add_target('https://example.org', authorized=True)
    job = repo.create_job(target.url, 'demo')
    claimed = repo.claim_next_scan_job('worker', lease_seconds=30)
    assert claimed.id == job.id
    return repo, job.id


def test_atomic_commit(tmp_path):
    repo, jid = setup(tmp_path)
    artifact, job = repo.commit_claimed_scan_result(jid, 'worker', 1, 'demo', {'ok': True})
    assert artifact['job_id'] == jid
    assert job.status == 'completed'
    assert len(repo.list_scan_artifacts(jid)) == 1


def test_wrong_worker_cannot_commit(tmp_path):
    repo, jid = setup(tmp_path)
    with pytest.raises(RuntimeError):
        repo.commit_claimed_scan_result(jid, 'other', 1, 'demo', {'ok': True})
    assert not repo.list_scan_artifacts(jid)


def test_wrong_attempt_cannot_commit(tmp_path):
    repo, jid = setup(tmp_path)
    with pytest.raises(RuntimeError):
        repo.commit_claimed_scan_result(jid, 'worker', 2, 'demo', {'ok': True})
    assert not repo.list_scan_artifacts(jid)


def test_cancelled_job_has_no_artifact(tmp_path):
    repo, jid = setup(tmp_path)
    repo.cancel_scan_job(jid)
    artifact, job = repo.commit_claimed_scan_result(jid, 'worker', 1, 'demo', {'ok': True})
    assert artifact is None
    assert job.status == 'cancelled'
    assert not repo.list_scan_artifacts(jid)


def test_invalid_payload_rolls_back(tmp_path):
    repo, jid = setup(tmp_path)
    with pytest.raises(ValueError):
        repo.commit_claimed_scan_result(jid, 'worker', 0, 'demo', {'ok': True})
    assert repo.get_job(jid).status == 'running'
