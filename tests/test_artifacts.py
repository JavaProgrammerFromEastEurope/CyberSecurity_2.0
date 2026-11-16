import json
import sqlite3

import pytest

from cybersec.repository import Repository
from cybersec.runner import JobRunner


def setup_repo(tmp_path):
    repo = Repository(tmp_path / "artifacts.db")
    repo.add_target("https://example.com", authorized=True)
    job = repo.create_job("https://example.com", "demo")
    return repo, job


def test_artifact_retention_is_idempotent_and_hashes_canonical_json(tmp_path):
    repo, job = setup_repo(tmp_path)
    first = repo.store_scan_artifact(job.id, "demo", {"b": 2, "a": 1})
    second = repo.store_scan_artifact(job.id, "demo", '{"a":1,"b":2}')
    assert first["id"] == second["id"]
    assert len(repo.list_scan_artifacts(job.id)) == 1
    assert first["payload_format"] == "json"
    assert json.loads(first["payload"]) == {"a": 1, "b": 2}


def test_malformed_payload_is_preserved_as_corrupt_text(tmp_path):
    repo, job = setup_repo(tmp_path)
    artifact = repo.store_scan_artifact(job.id, "nuclei", '{"template":"broken"')
    assert artifact["status"] == "corrupt"
    assert artifact["payload_format"] == "text"
    assert artifact["payload"] == '{"template":"broken"'


def test_partial_status_and_metadata_are_retained(tmp_path):
    repo, job = setup_repo(tmp_path)
    artifact = repo.store_scan_artifact(
        job.id, "zap", {"alerts": [1]}, status="partial", metadata={"reason": "timeout"}
    )
    assert artifact["status"] == "partial"
    assert repo.list_scan_artifacts(job.id)[0]["metadata"] == {"reason": "timeout"}


def test_artifact_requires_existing_job(tmp_path):
    repo, _ = setup_repo(tmp_path)
    with pytest.raises(ValueError, match="does not exist"):
        repo.store_scan_artifact(999, "demo", {})


def test_runner_stores_result_artifact(tmp_path):
    repo, job = setup_repo(tmp_path)
    result = JobRunner(repo).run(job.id)
    artifacts = repo.list_scan_artifacts(job.id)
    assert result.status == "completed"
    assert len(artifacts) == 1
    payload = json.loads(artifacts[0]["payload"])
    assert payload["raw_output"]["network_requests"] == 0
    assert artifacts[0]["metadata"]["finding_count"] == 0


def test_old_database_gets_provenance_columns_and_artifact_table(tmp_path):
    path = tmp_path / "legacy.db"
    db = sqlite3.connect(path)
    db.executescript("""
        CREATE TABLE targets (id INTEGER PRIMARY KEY AUTOINCREMENT, url TEXT NOT NULL UNIQUE,
            hostname TEXT NOT NULL, authorized INTEGER NOT NULL DEFAULT 0,
            created_at TEXT NOT NULL DEFAULT '2025-01-01T00:00:00Z');
        CREATE TABLE scan_jobs (id INTEGER PRIMARY KEY AUTOINCREMENT, target_id INTEGER NOT NULL,
            tool TEXT NOT NULL, status TEXT NOT NULL DEFAULT 'queued', created_at TEXT NOT NULL DEFAULT '2025-01-01T00:00:00Z',
            started_at TEXT, finished_at TEXT, error TEXT);
        CREATE TABLE normalized_findings (id INTEGER PRIMARY KEY AUTOINCREMENT, target_id INTEGER NOT NULL,
            job_id INTEGER, title TEXT NOT NULL, severity TEXT NOT NULL, confidence TEXT NOT NULL,
            url TEXT NOT NULL, vuln_type TEXT NOT NULL, parameter TEXT, evidence TEXT, recommendation TEXT,
            source_tool TEXT NOT NULL, created_at TEXT NOT NULL DEFAULT '2025-01-01T00:00:00Z');
    """)
    db.commit()
    db.close()
    repo = Repository(path)
    with sqlite3.connect(path) as db:
        columns = {row[1] for row in db.execute("PRAGMA table_info(normalized_findings)")}
        tables = {row[0] for row in db.execute("SELECT name FROM sqlite_master WHERE type='table'")}
    assert {"fingerprint", "source_id", "template_id", "observed_at"} <= columns
    assert "scan_artifacts" in tables


def test_normalized_finding_keeps_source_provenance(tmp_path):
    repo, job = setup_repo(tmp_path)
    finding = repo.add_finding(
        "https://example.com", "Example alert", "Medium", "Tentative", "TLS Misconfiguration",
        source_tool="nuclei", job_id=job.id, source_id="scan-result-17",
        template_id="http/misconfig/example.yaml", observed_at="2026-10-23T10:15:00Z",
    )
    row = next(item for item in repo.export_data()["findings"] if item["id"] == finding.id)
    assert row["job_id"] == job.id
    assert row["source_id"] == "scan-result-17"
    assert row["template_id"] == "http/misconfig/example.yaml"
    assert row["observed_at"] == "2026-10-23T10:15:00Z"
