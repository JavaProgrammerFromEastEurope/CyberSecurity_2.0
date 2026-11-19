import json

from cybersec.artifacts import import_artifact_file
from cybersec.repository import Repository
from cybersec.validation import build_export_manifest, validate_payload, verify_export_manifest


def test_validate_supported_findings_payload():
    summary = validate_payload({"findings": [{"title": "XSS"}]})
    assert summary["valid"] is True
    assert summary["recognized_format"] is True
    assert summary["finding_candidates"] == 1


def test_validate_unsupported_json_shape_is_explained():
    summary = validate_payload({"unexpected": [1, 2]})
    assert summary["valid"] is False
    assert "not a supported" in summary["issues"][0]


def test_import_nuclei_jsonl_and_replay(tmp_path):
    repo = Repository(tmp_path / "db.sqlite")
    repo.add_target("https://example.com", authorized=True)
    job = repo.create_job("https://example.com", "nuclei")
    source = tmp_path / "nuclei.jsonl"
    source.write_text('\n'.join([
        json.dumps({"template-id": "http/test.yaml", "matched-at": "https://example.com/a", "info": {"name": "Test", "severity": "medium"}}),
        json.dumps({"template-id": "http/other.yaml", "matched-at": "https://example.com/b", "info": {"name": "Other", "severity": "low"}}),
    ]), encoding="utf-8")
    artifact = import_artifact_file(repo, job.id, "nuclei", source)
    artifact = repo.get_scan_artifact(artifact["id"])
    assert artifact["payload_format"] == "json"
    assert artifact["metadata"]["source_format"] == "jsonl"
    assert len(json.loads(artifact["payload"])) == 2
    assert validate_payload(json.loads(artifact["payload"]))["finding_candidates"] == 2


def test_manifest_verifies_and_detects_tampering(tmp_path):
    output = tmp_path / "export.json"
    data = {"schema_version": 4, "targets": [{}], "jobs": [], "findings": [], "scan_artifacts": []}
    output.write_text(json.dumps(data) + "\n", encoding="utf-8")
    manifest_path = tmp_path / "export.manifest.json"
    manifest_path.write_text(json.dumps(build_export_manifest(output, data)), encoding="utf-8")
    assert verify_export_manifest(output, manifest_path)["valid"] is True
    output.write_text("tampered", encoding="utf-8")
    result = verify_export_manifest(output, manifest_path)
    assert result["valid"] is False
    assert result["checks"]["sha256_matches"] is False
