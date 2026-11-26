"""Stage 60: conservative external-scanner crash recovery policy."""
from concurrent.futures import ThreadPoolExecutor
import pytest
from cybersec.db import connect
from cybersec.repository import Repository


def setup(tmp_path):
    repo = Repository(tmp_path / 'recovery.sqlite')
    repo.add_target('https://example.test', authorized=True)
    return repo


def expire(repo, job_id):
    with connect(repo.db_path) as db:
        db.execute("UPDATE scan_jobs SET lease_until='2000-01-01T00:00:00.000Z' WHERE id=?", (job_id,))


def test_external_lease_expiry_does_not_relaunch(tmp_path):
    repo = setup(tmp_path)
    job = repo.create_job('https://example.test', 'nuclei')
    assert repo.claim_next_scan_job('a', lease_seconds=5).id == job.id
    expire(repo, job.id)
    assert repo.claim_next_scan_job('b', lease_seconds=5) is None
    assert repo.get_job(job.id).status == 'failed'
    with connect(repo.db_path) as db:
        row = db.execute('SELECT attempt_count, error FROM scan_jobs WHERE id=?', (job.id,)).fetchone()
    assert row['attempt_count'] == 1
    assert 'manual recovery required' in row['error']


def test_demo_can_be_reclaimed(tmp_path):
    repo = setup(tmp_path)
    job = repo.create_job('https://example.test', 'demo')
    repo.claim_next_scan_job('a', lease_seconds=5)
    expire(repo, job.id)
    assert repo.claim_next_scan_job('b', lease_seconds=5).id == job.id


def test_sqlmap_not_claimed_by_generic_worker(tmp_path):
    repo = setup(tmp_path)
    repo.create_job('https://example.test', 'sqlmap')
    assert repo.claim_next_scan_job('a') is None


def test_recovery_requires_acknowledged_stopped_process(tmp_path):
    repo = setup(tmp_path)
    job = repo.create_job('https://example.test', 'zap')
    repo.claim_next_scan_job('a', lease_seconds=5)
    expire(repo, job.id)
    repo.claim_next_scan_job('b', lease_seconds=5)
    with pytest.raises(PermissionError):
        repo.request_manual_scan_recovery(job.id, acknowledged_by='operator', external_process_stopped=False)
    recovered = repo.request_manual_scan_recovery(job.id, acknowledged_by='operator', external_process_stopped=True)
    assert recovered.id != job.id and recovered.status == 'queued'
    with connect(repo.db_path) as db:
        audit = db.execute('SELECT * FROM scan_recovery_audit WHERE new_job_id=?', (recovered.id,)).fetchone()
    assert audit['old_job_id'] == job.id and audit['acknowledged_by'] == 'operator'


def test_concurrent_recovery_claims_one_new_job(tmp_path):
    repo = setup(tmp_path)
    job = repo.create_job('https://example.test', 'nuclei')
    repo.claim_next_scan_job('a', lease_seconds=5)
    expire(repo, job.id)
    repo.claim_next_scan_job('b', lease_seconds=5)
    recovered = repo.request_manual_scan_recovery(job.id, acknowledged_by='operator', external_process_stopped=True)
    with ThreadPoolExecutor(max_workers=2) as pool:
        claims = list(pool.map(lambda worker: repo.claim_next_scan_job(worker), ['w1', 'w2']))
    assert [x.id for x in claims if x] == [recovered.id]
