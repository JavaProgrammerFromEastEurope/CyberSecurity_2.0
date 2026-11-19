import base64
import json
from unittest import mock

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from cybersec.repository import Repository


def _keys():
    private = Ed25519PrivateKey.generate()
    private_b64 = base64.b64encode(private.private_bytes(
        serialization.Encoding.Raw, serialization.PrivateFormat.Raw, serialization.NoEncryption()
    )).decode()
    public_b64 = base64.b64encode(private.public_key().public_bytes(
        serialization.Encoding.Raw, serialization.PublicFormat.Raw
    )).decode()
    return private_b64, public_b64


def _repo_with_key(tmp_path):
    repo = Repository(tmp_path / "checkpoint.db")
    private, public = _keys()
    repo.register_risk_policy_evidence_signing_key("checkpoint-key", public, "key-admin")
    return repo, private, public


def test_signed_checkpoint_verifies_and_survives_later_appends(tmp_path):
    repo, private, public = _repo_with_key(tmp_path)
    evaluation = repo.evaluate_risk_intelligence_policy("analyst")
    evidence = repo.create_risk_policy_evidence(evaluation["id"], "auditor")
    repo.export_risk_policy_evidence_bundle(evidence["id"], actor="exporter")
    checkpoint = repo.create_risk_policy_evidence_custody_checkpoint("checkpoint-key", private, "auditor")
    assert checkpoint["event_count"] == 1
    result = repo.verify_risk_policy_evidence_custody_checkpoint(checkpoint, public)
    assert result["valid"] is True
    assert result["signature_valid"] is True
    assert result["chain_prefix_valid"] is True
    # A later event must not invalidate an externally retained checkpoint for its earlier prefix.
    repo._record_policy_evidence_custody("bundle_verified", "later-user", evidence["id"], evaluation["id"], "a" * 64, {"valid": True})
    assert repo.verify_risk_policy_evidence_custody_checkpoint(checkpoint, public)["valid"] is True


def test_checkpoint_detects_rewritten_prefix_and_tampering(tmp_path):
    repo, private, public = _repo_with_key(tmp_path)
    evaluation = repo.evaluate_risk_intelligence_policy("analyst")
    evidence = repo.create_risk_policy_evidence(evaluation["id"], "auditor")
    repo.export_risk_policy_evidence_bundle(evidence["id"])
    checkpoint = repo.create_risk_policy_evidence_custody_checkpoint("checkpoint-key", private)
    altered = dict(checkpoint)
    altered["head_hash"] = "0" * 64
    assert repo.verify_risk_policy_evidence_custody_checkpoint(altered, public)["valid"] is False
    assert repo.verify_risk_policy_evidence_custody_checkpoint(checkpoint, _keys()[1])["signature_valid"] is False
    with pytest.raises(ValueError, match="refusing to checkpoint"):
        with mock.patch.object(repo, "verify_risk_policy_evidence_custody_chain", return_value={"valid": False}):
            repo.create_risk_policy_evidence_custody_checkpoint("checkpoint-key", private)


def test_checkpoint_requires_active_registered_matching_key(tmp_path):
    repo, private, public = _repo_with_key(tmp_path)
    other_private, _ = _keys()
    with pytest.raises(ValueError, match="does not match"):
        repo.create_risk_policy_evidence_custody_checkpoint("checkpoint-key", other_private)
    repo.revoke_risk_policy_evidence_signing_key("checkpoint-key", "admin", "rotation")
    with pytest.raises(ValueError, match="not revoked"):
        repo.create_risk_policy_evidence_custody_checkpoint("checkpoint-key", private)


def test_checkpoint_index_does_not_disclose_signature_or_public_key(tmp_path):
    repo, private, _ = _repo_with_key(tmp_path)
    checkpoint = repo.create_risk_policy_evidence_custody_checkpoint("checkpoint-key", private)
    listed = repo.list_risk_policy_evidence_custody_checkpoints()
    assert listed[0]["checkpoint_id"] == checkpoint["checkpoint_id"]
    assert "signature_b64" not in listed[0]
    assert "public_key_b64" not in listed[0]


def test_checkpoint_api_is_protected_and_documented(tmp_path):
    import threading
    import urllib.error
    import urllib.request
    from http.server import ThreadingHTTPServer
    from cybersec.api import API_VERSION, make_handler

    repo, private, public = _repo_with_key(tmp_path)
    token = "stage48-checkpoint-token"
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
        assert call("/api/v1/risk/policy/evidence/custody/checkpoints", auth=False)[0] == 401
        status, checkpoint = call("/api/v1/risk/policy/evidence/custody/checkpoints", "POST", {
            "key_id": "checkpoint-key", "signing_private_key": private, "actor": "auditor"
        })
        assert status == 201 and checkpoint["algorithm"] == "Ed25519"
        status, verification = call("/api/v1/risk/policy/evidence/custody/checkpoints/verify", "POST", {
            "checkpoint": checkpoint, "trusted_public_key": public
        })
        assert status == 200 and verification["valid"] is True
        assert call("/api/v1/risk/policy/evidence/custody/checkpoints")[1][0]["checkpoint_id"] == checkpoint["checkpoint_id"]
        spec = call("/openapi.json")[1]
        assert "/api/v1/risk/policy/evidence/custody/checkpoints" in spec["paths"]
        assert "/api/v1/risk/policy/evidence/custody/checkpoints/verify" in spec["paths"]
    finally:
        server.shutdown()
        thread.join(timeout=3)
        server.server_close()
