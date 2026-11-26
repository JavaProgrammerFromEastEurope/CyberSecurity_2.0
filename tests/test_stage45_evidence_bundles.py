import copy
import json
import threading
import urllib.error
import urllib.request
from http.server import ThreadingHTTPServer

import pytest

from cybersec.api import API_VERSION, make_handler
from cybersec.db import connect
from cybersec.repository import Repository


def _evidence(repo):
    evaluation = repo.evaluate_risk_intelligence_policy("stage45-test")
    return repo.create_risk_policy_evidence(evaluation["id"], "auditor")


def test_unsigned_bundle_round_trip_verifies_without_mutation(tmp_path):
    repo = Repository(tmp_path / "bundle.db")
    evidence = _evidence(repo)
    before = repo.list_risk_policy_evidence()
    bundle = repo.export_risk_policy_evidence_bundle(evidence["id"])
    result = repo.verify_risk_policy_evidence_bundle(bundle)
    assert result["valid"] is True
    assert result["evidence_integrity_valid"] is True
    assert result["bundle_integrity_valid"] is True
    assert result["signature_algorithm"] == "none"
    assert result["signature_valid"] is None
    assert repo.list_risk_policy_evidence() == before


def test_hmac_signed_bundle_requires_matching_shared_key(tmp_path):
    repo = Repository(tmp_path / "signed-bundle.db")
    evidence = _evidence(repo)
    bundle = repo.export_risk_policy_evidence_bundle(evidence["id"], "a-long-test-key-123")
    assert bundle["signature"]["algorithm"] == "HMAC-SHA256"
    assert repo.verify_risk_policy_evidence_bundle(bundle, "a-long-test-key-123")["valid"] is True
    assert repo.verify_risk_policy_evidence_bundle(bundle)["valid"] is False
    assert repo.verify_risk_policy_evidence_bundle(bundle, "another-long-key-123")["signature_valid"] is False
    assert "a-long-test-key-123" not in json.dumps(bundle)


def test_bundle_tampering_is_detected(tmp_path):
    repo = Repository(tmp_path / "tampered-bundle.db")
    evidence = _evidence(repo)
    bundle = repo.export_risk_policy_evidence_bundle(evidence["id"])
    changed = copy.deepcopy(bundle)
    changed["evidence"]["snapshot"]["policy"]["summary"] = {"changed": True}
    result = repo.verify_risk_policy_evidence_bundle(changed)
    assert result["valid"] is False
    assert result["evidence_integrity_valid"] is False
    assert result["bundle_integrity_valid"] is False


def test_bundle_export_refuses_corrupted_database_evidence(tmp_path):
    repo = Repository(tmp_path / "corrupt.db")
    evidence = _evidence(repo)
    with connect(repo.db_path) as db:
        db.execute("UPDATE risk_policy_evidence SET snapshot_json=? WHERE id=?", ('{"bad":true}', evidence["id"]))
    with pytest.raises(ValueError, match="integrity check failed"):
        repo.export_risk_policy_evidence_bundle(evidence["id"])


def test_bundle_validation_and_key_length(tmp_path):
    repo = Repository(tmp_path / "validation.db")
    evidence = _evidence(repo)
    with pytest.raises(ValueError, match="16 UTF-8 bytes"):
        repo.export_risk_policy_evidence_bundle(evidence["id"], "short")
    with pytest.raises(ValueError, match="JSON object"):
        repo.verify_risk_policy_evidence_bundle([])
    with pytest.raises(ValueError, match="Unsupported evidence bundle"):
        repo.verify_risk_policy_evidence_bundle({"format": "wrong", "schema_version": 1})


def test_bundle_api_is_protected_documented_and_non_mutating(tmp_path):
    repo = Repository(tmp_path / "bundle-api.db")
    token = "stage45-api-test-token"
    server = ThreadingHTTPServer(("127.0.0.1", 0), make_handler(repo, token))
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    base = f"http://127.0.0.1:{server.server_address[1]}"

    def call(path, method="GET", body=None, auth=True):
        data = json.dumps(body).encode() if body is not None else None
        headers = {"Content-Type": "application/json"}
        if auth:
            headers["Authorization"] = "Bearer " + token
        req = urllib.request.Request(base + path, data=data, headers=headers, method=method)
        try:
            with urllib.request.urlopen(req, timeout=3) as response:
                return response.status, json.loads(response.read())
        except urllib.error.HTTPError as exc:
            return exc.code, json.loads(exc.read())

    try:
        assert API_VERSION == "2.33.0"
        assert call("/api/v1/risk/policy/evidence/bundles/verify", "POST", {"bundle": {}}, auth=False)[0] == 401
        evidence = _evidence(repo)
        status, bundle = call(f"/api/v1/risk/policy/evidence/{evidence['id']}/bundle", "POST", {"signing_key": "test-key-long-enough-123"})
        assert status == 200
        status, result = call("/api/v1/risk/policy/evidence/bundles/verify", "POST", {"bundle": bundle, "signing_key": "test-key-long-enough-123"})
        assert status == 200 and result["valid"] is True
        spec = call("/openapi.json")[1]
        assert "/api/v1/risk/policy/evidence/bundles/verify" in spec["paths"]
    finally:
        server.shutdown()
        thread.join(timeout=3)
        server.server_close()
