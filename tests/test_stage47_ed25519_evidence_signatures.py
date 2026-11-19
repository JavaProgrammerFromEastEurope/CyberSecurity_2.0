import base64
import json
import threading
import urllib.error
import urllib.request
from http.server import ThreadingHTTPServer

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from cybersec.api import API_VERSION, make_handler
from cybersec.repository import Repository


def _keys():
    private = Ed25519PrivateKey.generate()
    private_raw = private.private_bytes(serialization.Encoding.Raw, serialization.PrivateFormat.Raw, serialization.NoEncryption())
    public_raw = private.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
    return base64.b64encode(private_raw).decode(), base64.b64encode(public_raw).decode()


def _evidence(repo):
    evaluation = repo.evaluate_risk_intelligence_policy("stage47-test")
    return repo.create_risk_policy_evidence(evaluation["id"], "auditor")


def test_ed25519_bundle_sign_and_verify_with_registered_key(tmp_path):
    repo = Repository(tmp_path / "ed25519.db")
    evidence = _evidence(repo)
    private, public = _keys()
    registered = repo.register_risk_policy_evidence_signing_key("compliance-2026", public, "key-admin")
    assert registered["algorithm"] == "Ed25519" and registered["revoked"] is False
    bundle = repo.export_risk_policy_evidence_bundle(evidence["id"], actor="signer", signing_private_key=private, key_id="compliance-2026")
    assert bundle["signature"]["algorithm"] == "Ed25519"
    assert "private" not in json.dumps(bundle).lower()
    result = repo.verify_risk_policy_evidence_bundle(bundle, actor="verifier")
    assert result["valid"] is True
    assert result["signature_valid"] is True
    assert result["key_id"] == "compliance-2026"


def test_ed25519_unknown_revoked_and_wrong_keys_fail_verification(tmp_path):
    repo = Repository(tmp_path / "ed25519-revoke.db")
    evidence = _evidence(repo)
    private, public = _keys()
    repo.register_risk_policy_evidence_signing_key("signer-a", public)
    bundle = repo.export_risk_policy_evidence_bundle(evidence["id"], signing_private_key=private, key_id="signer-a")
    assert repo.verify_risk_policy_evidence_bundle(bundle)["valid"] is True
    repo.revoke_risk_policy_evidence_signing_key("signer-a", "security-admin", "compromised key")
    result = repo.verify_risk_policy_evidence_bundle(bundle)
    assert result["valid"] is False and result["signature_valid"] is False
    with pytest.raises(ValueError, match="cannot be reactivated"):
        repo.register_risk_policy_evidence_signing_key("signer-a", public)
    with pytest.raises(ValueError, match="registered and not revoked"):
        repo.export_risk_policy_evidence_bundle(evidence["id"], signing_private_key=private, key_id="signer-a")


def test_ed25519_tamper_and_invalid_key_inputs(tmp_path):
    repo = Repository(tmp_path / "ed25519-invalid.db")
    evidence = _evidence(repo)
    private, public = _keys()
    repo.register_risk_policy_evidence_signing_key("trusted", public)
    bundle = repo.export_risk_policy_evidence_bundle(evidence["id"], signing_private_key=private, key_id="trusted")
    bundle["evidence"]["snapshot"]["tampered"] = True
    result = repo.verify_risk_policy_evidence_bundle(bundle)
    assert result["valid"] is False
    assert result["bundle_integrity_valid"] is False
    with pytest.raises(ValueError, match="exactly 32 bytes"):
        repo.register_risk_policy_evidence_signing_key("bad", base64.b64encode(b"short").decode())
    with pytest.raises(ValueError, match="key_id is required"):
        repo.export_risk_policy_evidence_bundle(evidence["id"], signing_private_key=private)


def test_signing_key_audit_and_revocation_metadata(tmp_path):
    repo = Repository(tmp_path / "key-audit.db")
    _, public = _keys()
    repo.register_risk_policy_evidence_signing_key("audit-key", public, "alice")
    repo.revoke_risk_policy_evidence_signing_key("audit-key", "bob", "rotation")
    events = repo.list_risk_policy_evidence_signing_key_audit("audit-key")
    assert [e["action"] for e in reversed(events)] == ["registered", "revoked"]
    assert repo.list_risk_policy_evidence_signing_keys(include_revoked=False) == []


def test_ed25519_api_is_protected_and_documented(tmp_path):
    repo = Repository(tmp_path / "ed25519-api.db")
    token = "stage47-api-token"
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
        _, public = _keys()
        assert API_VERSION == "2.33.0"
        assert call("/api/v1/risk/policy/evidence/signing-keys", auth=False)[0] == 401
        status, key = call("/api/v1/risk/policy/evidence/signing-keys", "POST", {"key_id": "api-key", "public_key": public, "actor": "admin"})
        assert status == 201 and key["key_id"] == "api-key"
        assert call("/api/v1/risk/policy/evidence/signing-keys")[1][0]["key_id"] == "api-key"
        spec = call("/openapi.json")[1]
        assert "/api/v1/risk/policy/evidence/signing-keys" in spec["paths"]
        assert "/api/v1/risk/policy/evidence/signing-keys/{key_id}/revoke" in spec["paths"]
    finally:
        server.shutdown()
        thread.join(timeout=3)
        server.server_close()


def test_export_rejects_private_key_that_does_not_match_registered_public_key(tmp_path):
    repo = Repository(tmp_path / "key-mismatch.db")
    evidence = _evidence(repo)
    private, public = _keys()
    other_private, _ = _keys()
    repo.register_risk_policy_evidence_signing_key("expected-key", public)
    with pytest.raises(ValueError, match="does not match the registered public key"):
        repo.export_risk_policy_evidence_bundle(evidence["id"], signing_private_key=other_private, key_id="expected-key")
