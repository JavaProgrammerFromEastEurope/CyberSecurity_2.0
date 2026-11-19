import hashlib
import json

import pytest

from cybersec.repository import Repository


def _evaluation(repo):
    # A valid empty evaluation is still useful evidence of a policy review with no rules.
    return repo.evaluate_risk_intelligence_policy("evidence-test")


def test_create_and_verify_immutable_policy_evidence(tmp_path):
    repo = Repository(tmp_path / "evidence.db")
    evaluation = _evaluation(repo)
    evidence = repo.create_risk_policy_evidence(evaluation["id"], "auditor")
    assert evidence["evaluation_id"] == evaluation["id"]
    assert evidence["created_by"] == "auditor"
    assert evidence["integrity_valid"] is True
    assert len(evidence["sha256"]) == 64
    canonical = json.dumps(evidence["snapshot"], ensure_ascii=False, sort_keys=True, separators=(",", ":"))
    assert hashlib.sha256(canonical.encode()).hexdigest() == evidence["sha256"]
    assert repo.verify_risk_policy_evidence(evidence["id"])["integrity_valid"] is True


def test_evidence_snapshot_survives_evaluation_retention_pruning(tmp_path):
    repo = Repository(tmp_path / "evidence-retention.db")
    evaluation = _evaluation(repo)
    evidence = repo.create_risk_policy_evidence(evaluation["id"])
    with repo.db_path.open("rb"):
        pass
    with __import__("cybersec.db", fromlist=["connect"]).connect(repo.db_path) as db:
        db.execute("UPDATE risk_intelligence_policy_evaluations SET created_at='2000-01-01T00:00:00Z' WHERE id=?", (evaluation["id"],))
    repo.set_risk_policy_retention(1)
    pruned = repo.prune_risk_policy_evaluations(dry_run=False)
    assert pruned["deleted"] == 1
    assert repo.get_risk_policy_evidence(evidence["id"])["integrity_valid"] is True


def test_json_and_csv_compliance_exports(tmp_path):
    repo = Repository(tmp_path / "evidence-export.db")
    evaluation = _evaluation(repo)
    evidence = repo.create_risk_policy_evidence(evaluation["id"])
    json_report = repo.export_risk_policy_compliance_report(evidence["id"], "json")
    csv_report = repo.export_risk_policy_compliance_report(evidence["id"], "csv")
    assert json_report["filename"].endswith(".json")
    assert json_report["report"]["evaluation"]["id"] == evaluation["id"]
    assert csv_report["filename"].endswith(".csv")
    assert csv_report["columns"][0] == "evidence_id"
    assert csv_report["rows"] == []
    with pytest.raises(ValueError, match="format must be json or csv"):
        repo.export_risk_policy_compliance_report(evidence["id"], "xml")


def test_evidence_rejects_missing_evaluation_and_invalid_ids(tmp_path):
    repo = Repository(tmp_path / "evidence-invalid.db")
    with pytest.raises(ValueError, match="does not exist"):
        repo.create_risk_policy_evidence(999)
    with pytest.raises(ValueError, match="positive integer"):
        repo.get_risk_policy_evidence(0)


def test_secret_like_fields_are_redacted_before_snapshot_persistence(tmp_path):
    repo = Repository(tmp_path / "evidence-redaction.db")
    redacted = repo._redact_policy_evidence({"api_key": "abc", "nested": {"refresh_token": "def", "label": "safe"}})
    assert redacted == {"api_key": "[REDACTED]", "nested": {"refresh_token": "[REDACTED]", "label": "safe"}}


def test_evidence_api_is_protected_and_documented(tmp_path):
    import json
    import threading
    import urllib.error
    import urllib.request
    from http.server import ThreadingHTTPServer
    from cybersec.api import API_VERSION, make_handler

    repo = Repository(tmp_path / "evidence-api.db")
    token = "stage44-test-token"
    server = ThreadingHTTPServer(("127.0.0.1", 0), make_handler(repo, token))
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    base = f"http://127.0.0.1:{server.server_address[1]}"

    def call(path, method="GET", body=None, auth=True):
        data = json.dumps(body).encode() if body is not None else None
        headers = {"Content-Type": "application/json"}
        if auth:
            headers["Authorization"] = "Bearer " + token
        request = urllib.request.Request(base + path, data=data, headers=headers, method=method)
        try:
            with urllib.request.urlopen(request, timeout=3) as response:
                return response.status, json.loads(response.read())
        except urllib.error.HTTPError as exc:
            return exc.code, json.loads(exc.read())

    try:
        assert API_VERSION == "2.33.0"
        assert call("/api/v1/risk/policy/evidence", auth=False)[0] == 401
        evaluation = _evaluation(repo)
        status, evidence = call("/api/v1/risk/policy/evidence", "POST", {"evaluation_id": evaluation["id"], "actor": "auditor"})
        assert status == 201 and evidence["integrity_valid"]
        assert call(f"/api/v1/risk/policy/evidence/{evidence['id']}/verify")[1]["integrity_valid"]
        assert call(f"/api/v1/risk/policy/evidence/{evidence['id']}/report?format=csv")[1]["format"] == "csv"
        spec = call("/openapi.json")[1]
        assert "/api/v1/risk/policy/evidence/{evidence_id}/verify" in spec["paths"]
    finally:
        server.shutdown()
        thread.join(timeout=3)
        server.server_close()


def test_tampered_evidence_is_detected_and_export_refused(tmp_path):
    from cybersec.db import connect

    repo = Repository(tmp_path / "evidence-tamper.db")
    evaluation = _evaluation(repo)
    evidence = repo.create_risk_policy_evidence(evaluation["id"])
    with connect(repo.db_path) as db:
        db.execute("UPDATE risk_policy_evidence SET snapshot_json=? WHERE id=?", ('{"tampered":true}', evidence["id"]))
    assert repo.verify_risk_policy_evidence(evidence["id"])["integrity_valid"] is False
    with pytest.raises(ValueError, match="integrity check failed"):
        repo.export_risk_policy_compliance_report(evidence["id"])
