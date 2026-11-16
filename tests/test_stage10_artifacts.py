import json

from cybersec.artifacts import import_artifact_file, replay_artifact
from cybersec.repository import Repository
from cybersec.reports import render_html_report


def setup_repo(tmp_path, tool="nuclei"):
    repo = Repository(tmp_path / "stage10.db")
    repo.add_target("https://example.com", authorized=True)
    job = repo.create_job("https://example.com", tool)
    return repo, job


def test_import_json_and_search_artifacts(tmp_path):
    repo, job = setup_repo(tmp_path)
    source = tmp_path / "scan.json"
    source.write_text(json.dumps({"findings": [{"title": "XSS", "severity": "High"}]}))
    first = import_artifact_file(repo, job.id, "nuclei", source)
    second = import_artifact_file(repo, job.id, "nuclei", source)
    assert first["id"] == second["id"]
    assert len(repo.search_scan_artifacts(source_tool="nuclei", query="XSS")) == 1


def test_import_malformed_text_is_preserved(tmp_path):
    repo, job = setup_repo(tmp_path)
    source = tmp_path / "broken.json"
    source.write_text('{"incomplete":', encoding="utf-8")
    artifact = import_artifact_file(repo, job.id, "nuclei", source)
    assert artifact["status"] == "corrupt"
    assert artifact["payload_format"] == "text"
    assert artifact["payload"] == '{"incomplete":'


def test_replay_imports_in_scope_and_skips_other_origin(tmp_path):
    repo, job = setup_repo(tmp_path)
    artifact = repo.store_scan_artifact(job.id, "nuclei", {"findings": [
        {"title": "In-scope issue", "severity": "High", "url": "https://example.com/a", "template-id": "http/test.yaml"},
        {"title": "Out-of-scope issue", "severity": "Critical", "url": "https://other.example/a"},
    ]})
    result = replay_artifact(repo, artifact["id"])
    assert result["accepted"] == 1
    assert result["skipped_out_of_scope"] == 1
    findings = repo.list_findings()
    assert len(findings) == 1
    assert findings[0].title == "In-scope issue"


def test_replay_is_idempotent_for_findings(tmp_path):
    repo, job = setup_repo(tmp_path)
    artifact = repo.store_scan_artifact(job.id, "nuclei", {"findings": [
        {"title": "Issue", "severity": "Medium", "url": "https://example.com/a", "template-id": "xss/test"}
    ]})
    replay_artifact(repo, artifact["id"])
    replay_artifact(repo, artifact["id"])
    assert len(repo.list_findings()) == 1


def test_text_artifact_cannot_be_replayed(tmp_path):
    repo, job = setup_repo(tmp_path)
    artifact = repo.store_scan_artifact(job.id, "nuclei", "not json")
    try:
        replay_artifact(repo, artifact["id"])
    except ValueError as exc:
        assert "not JSON" in str(exc)
    else:
        raise AssertionError("Expected text artifact replay to fail")


def test_export_and_technical_report_include_artifact_reference(tmp_path):
    repo, job = setup_repo(tmp_path)
    finding = repo.add_finding("https://example.com", "Issue", "Low", "Unknown", "Misconfiguration",
                               url="https://example.com/a", job_id=job.id, source_tool="nuclei")
    artifact = repo.store_scan_artifact(job.id, "nuclei", {"findings": []})
    data = repo.export_data()
    exported = next(item for item in data["findings"] if item["id"] == finding.id)
    assert exported["source_artifact_ids"] == [artifact["id"]]
    html = render_html_report(data, profile="technical")
    assert f"#{artifact['id']}" in html
