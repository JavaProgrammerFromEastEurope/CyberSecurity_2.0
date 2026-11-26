import copy

import pytest

from cybersec.repository import Repository


def _bundle(repo):
    evaluation = repo.evaluate_risk_intelligence_policy(actor="policy-test")
    evidence = repo.create_risk_policy_evidence(evaluation["id"], actor="evidence-author")
    return evidence, repo.export_risk_policy_evidence_bundle(evidence["id"], actor="exporter")


def test_bundle_export_records_provenance_and_hash_chained_custody(tmp_path):
    repo = Repository(tmp_path / "custody.db")
    evidence, bundle = _bundle(repo)
    assert bundle["manifest"]["source_evidence_created_by"] == "evidence-author"
    assert bundle["manifest"]["source_evidence_created_at"] == evidence["created_at"]
    events = repo.list_risk_policy_evidence_custody()
    assert len(events) == 1
    assert events[0]["event_type"] == "bundle_exported"
    assert events[0]["actor"] == "exporter"
    assert repo.verify_risk_policy_evidence_custody_chain()["valid"] is True


def test_verification_records_event_and_flags_repeated_valid_bundle(tmp_path):
    repo = Repository(tmp_path / "replay.db")
    _, bundle = _bundle(repo)
    first = repo.verify_risk_policy_evidence_bundle(bundle, actor="reviewer-a")
    second = repo.verify_risk_policy_evidence_bundle(bundle, actor="reviewer-b")
    assert first["valid"] is True and first["replay_detected"] is False
    assert second["valid"] is True and second["replay_detected"] is True
    events = repo.list_risk_policy_evidence_custody(bundle_sha256=bundle["manifest"]["bundle_sha256"])
    assert [event["event_type"] for event in events] == ["bundle_verified", "bundle_verified", "bundle_exported"]
    assert repo.verify_risk_policy_evidence_custody_chain()["valid"] is True


def test_invalid_signature_attempt_is_audited(tmp_path):
    repo = Repository(tmp_path / "bad-signature.db")
    _, bundle = _bundle(repo)
    # The valid bundle has no signature, so a modified digest fails integrity.
    altered = copy.deepcopy(bundle)
    altered["manifest"]["bundle_sha256"] = "0" * 64
    result = repo.verify_risk_policy_evidence_bundle(altered, actor="reviewer")
    assert result["valid"] is False
    assert repo.list_risk_policy_evidence_custody()[0]["event_type"] == "bundle_verification_failed"


def test_custody_chain_detects_row_tampering(tmp_path):
    repo = Repository(tmp_path / "tamper-chain.db")
    _, bundle = _bundle(repo)
    repo.verify_risk_policy_evidence_bundle(bundle)
    assert repo.verify_risk_policy_evidence_custody_chain()["valid"] is True
    from cybersec.db import connect
    with connect(repo.db_path) as db:
        db.execute("UPDATE risk_policy_evidence_custody SET actor='tampered' WHERE id=1")
    result = repo.verify_risk_policy_evidence_custody_chain()
    assert result["valid"] is False
    assert result["failed_event_id"] == 1


def test_custody_actor_validation(tmp_path):
    repo = Repository(tmp_path / "actor.db")
    evidence, _ = _bundle(repo)
    with pytest.raises(ValueError, match="actor"):
        repo.export_risk_policy_evidence_bundle(evidence["id"], actor="")


def test_custody_api_is_protected_documented_and_returns_chain_state(tmp_path):
    import json
    import threading
    import urllib.error
    import urllib.request
    from http.server import ThreadingHTTPServer
    from cybersec.api import API_VERSION, make_handler

    repo = Repository(tmp_path / "custody-api.db")
    evaluation = repo.evaluate_risk_intelligence_policy("api-test")
    evidence = repo.create_risk_policy_evidence(evaluation["id"], "api-author")
    server = ThreadingHTTPServer(("127.0.0.1", 0), make_handler(repo, "stage46-api-token"))
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    base = f"http://127.0.0.1:{server.server_address[1]}"

    def call(path, method="GET", body=None, auth=True):
        headers = {"Content-Type": "application/json"}
        if auth:
            headers["Authorization"] = "Bearer stage46-api-token"
        request = urllib.request.Request(base + path, data=json.dumps(body).encode() if body is not None else None, headers=headers, method=method)
        try:
            with urllib.request.urlopen(request, timeout=3) as response:
                return response.status, json.loads(response.read())
        except urllib.error.HTTPError as exc:
            return exc.code, json.loads(exc.read())

    try:
        assert API_VERSION == "2.33.0"
        assert call("/api/v1/risk/policy/evidence/custody", auth=False)[0] == 401
        status, bundle = call(f"/api/v1/risk/policy/evidence/{evidence['id']}/bundle", "POST", {"actor": "api-exporter"})
        assert status == 200
        status, result = call("/api/v1/risk/policy/evidence/bundles/verify", "POST", {"bundle": bundle, "actor": "api-reviewer"})
        assert status == 200 and result["valid"] is True
        assert call("/api/v1/risk/policy/evidence/custody/verify")[1]["valid"] is True
        spec = call("/openapi.json")[1]
        assert "/api/v1/risk/policy/evidence/custody" in spec["paths"]
        assert "/api/v1/risk/policy/evidence/custody/verify" in spec["paths"]
    finally:
        server.shutdown()
        thread.join(timeout=3)
        server.server_close()
