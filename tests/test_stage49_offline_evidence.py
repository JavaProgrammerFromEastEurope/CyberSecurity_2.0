import base64
import json
from pathlib import Path

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from cybersec.evidence_offline import verify_bundle, verify_checkpoint, verify_custody_events, verify_file
from cybersec.repository import Repository


def keys():
    private = Ed25519PrivateKey.generate()
    return (
        base64.b64encode(private.private_bytes(serialization.Encoding.Raw, serialization.PrivateFormat.Raw, serialization.NoEncryption())).decode(),
        base64.b64encode(private.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)).decode(),
    )


def test_offline_verifies_signed_bundle_without_database(tmp_path):
    repo = Repository(tmp_path / "source.db")
    evaluation = repo.evaluate_risk_intelligence_policy("analyst")
    evidence = repo.create_risk_policy_evidence(evaluation["id"], "auditor")
    private, public = keys()
    repo.register_risk_policy_evidence_signing_key("key-a", public)
    bundle = repo.export_risk_policy_evidence_bundle(evidence["id"], signing_private_key=private, key_id="key-a")
    result = verify_bundle(bundle, public)
    assert result["valid"] is True
    assert result["database_accessed"] is False
    assert verify_bundle(bundle, keys()[1])["signature_valid"] is False
    altered = json.loads(json.dumps(bundle))
    altered["evidence"]["snapshot"]["tampered"] = True
    assert verify_bundle(altered, public)["valid"] is False


def test_offline_verifies_checkpoint_signature_and_external_file(tmp_path):
    repo = Repository(tmp_path / "source.db")
    private, public = keys()
    repo.register_risk_policy_evidence_signing_key("checkpoint-key", public)
    evaluation = repo.evaluate_risk_intelligence_policy("analyst")
    evidence = repo.create_risk_policy_evidence(evaluation["id"], "auditor")
    repo.export_risk_policy_evidence_bundle(evidence["id"])
    checkpoint = repo.create_risk_policy_evidence_custody_checkpoint("checkpoint-key", private)
    assert verify_checkpoint(checkpoint, public)["valid"] is True
    checkpoint_path = tmp_path / "checkpoint.json"
    key_path = tmp_path / "trusted.pub"
    checkpoint_path.write_text(json.dumps(checkpoint), encoding="utf-8")
    key_path.write_text(public, encoding="utf-8")
    assert verify_file(checkpoint_path, key_path)["valid"] is True
    assert verify_file(checkpoint_path, key_path)["database_accessed"] is False


def test_rotation_registers_new_and_revokes_old_atomically(tmp_path):
    repo = Repository(tmp_path / "rotation.db")
    _, old_public = keys()
    _, new_public = keys()
    repo.register_risk_policy_evidence_signing_key("old", old_public, "admin")
    result = repo.rotate_risk_policy_evidence_signing_key("old", "new", new_public, "admin", "scheduled rotation")
    assert result["rotated"] is True
    items = {item["key_id"]: item for item in repo.list_risk_policy_evidence_signing_keys()}
    assert items["old"]["revoked"] is True
    assert items["new"]["revoked"] is False
    with pytest.raises(ValueError, match="already exists"):
        repo.rotate_risk_policy_evidence_signing_key("new", "old", old_public, "admin", "bad reuse")


def test_offline_checkpoint_requires_explicit_trusted_key():
    _, public = keys()
    with pytest.raises(ValueError, match="required"):
        verify_checkpoint({"format": "cybersec-custody-checkpoint", "schema_version": 1}, "")


def test_offline_checkpoint_checks_exported_custody_prefix(tmp_path):
    repo = Repository(tmp_path / "offline-chain.db")
    private, public = keys()
    repo.register_risk_policy_evidence_signing_key("chain-key", public)
    evaluation = repo.evaluate_risk_intelligence_policy("analyst")
    evidence = repo.create_risk_policy_evidence(evaluation["id"], "auditor")
    repo.export_risk_policy_evidence_bundle(evidence["id"])
    checkpoint = repo.create_risk_policy_evidence_custody_checkpoint("chain-key", private)
    events = repo.list_risk_policy_evidence_custody(limit=100)
    events.reverse()
    checkpoint_path, key_path, events_path = tmp_path / "checkpoint.json", tmp_path / "trusted.pub", tmp_path / "events.json"
    checkpoint_path.write_text(json.dumps(checkpoint), encoding="utf-8")
    key_path.write_text(public, encoding="utf-8")
    events_path.write_text(json.dumps(events), encoding="utf-8")
    result = verify_file(checkpoint_path, key_path, events_path)
    assert result["valid"] is True
    assert result["chain_prefix_valid"] is True
    altered_events = json.loads(json.dumps(events))
    altered_events[0]["actor"] = "tampered"
    events_path.write_text(json.dumps(altered_events), encoding="utf-8")
    assert verify_file(checkpoint_path, key_path, events_path)["valid"] is False


def test_rotation_api_is_protected_and_documented(tmp_path):
    import threading
    import urllib.error
    import urllib.request
    from http.server import ThreadingHTTPServer
    from cybersec.api import API_VERSION, make_handler

    repo = Repository(tmp_path / "rotation-api.db")
    _, old_public = keys()
    _, new_public = keys()
    repo.register_risk_policy_evidence_signing_key("old-api", old_public, "admin")
    token = "stage49-rotation-token"
    server = ThreadingHTTPServer(("127.0.0.1", 0), make_handler(repo, token))
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    base = f"http://127.0.0.1:{server.server_address[1]}"

    def post(path, body, auth=True):
        headers = {"Content-Type": "application/json"}
        if auth:
            headers["Authorization"] = "Bearer " + token
        request = urllib.request.Request(base + path, data=json.dumps(body).encode(), headers=headers, method="POST")
        try:
            with urllib.request.urlopen(request, timeout=3) as response:
                return response.status, json.loads(response.read())
        except urllib.error.HTTPError as exc:
            return exc.code, json.loads(exc.read())

    try:
        assert API_VERSION == "2.33.0"
        path = "/api/v1/risk/policy/evidence/signing-keys/rotate"
        body = {"old_key_id": "old-api", "new_key_id": "new-api", "new_public_key": new_public, "actor": "admin", "reason": "planned"}
        assert post(path, body, auth=False)[0] == 401
        status, result = post(path, body)
        assert status == 200 and result["rotated"] is True
        request = urllib.request.Request(base + "/openapi.json")
        with urllib.request.urlopen(request, timeout=3) as response:
            spec = json.loads(response.read())
        assert path in spec["paths"]
    finally:
        server.shutdown()
        thread.join(timeout=3)
        server.server_close()
