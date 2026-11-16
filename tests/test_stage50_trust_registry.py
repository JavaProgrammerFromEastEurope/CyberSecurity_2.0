import base64, json
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cybersec.repository import Repository
from cybersec.trust_registry import verify_snapshot, verify_file


def keys():
    private = Ed25519PrivateKey.generate()
    return (base64.b64encode(private.private_bytes(serialization.Encoding.Raw, serialization.PrivateFormat.Raw, serialization.NoEncryption())).decode(),
            base64.b64encode(private.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)).decode())


def test_signed_registry_snapshot_and_offline_audit_report(tmp_path):
    repo = Repository(tmp_path / "registry.db")
    private, public = keys()
    repo.register_risk_policy_evidence_signing_key("registry-signer", public, "admin")
    _, second_public = keys()
    repo.register_risk_policy_evidence_signing_key("evidence-key", second_public, "analyst")
    repo.revoke_risk_policy_evidence_signing_key("evidence-key", "admin", "retired")
    snapshot = repo.export_trust_registry_snapshot(private, "registry-signer", "auditor")
    result = verify_snapshot(snapshot, public)
    assert result["valid"] and result["key_count"] == 2
    assert result["audit_event_count"] >= 3
    assert result["private_key_exported"] is False
    path, pub = tmp_path / "snapshot.json", tmp_path / "trusted.pub"
    path.write_text(json.dumps(snapshot), encoding="utf-8"); pub.write_text(public, encoding="utf-8")
    report = verify_file(path, pub)
    assert report["verification"]["valid"] and len(report["key_history"]) == 2


def test_snapshot_tampering_and_wrong_key_fail(tmp_path):
    repo = Repository(tmp_path / "tamper.db")
    private, public = keys()
    repo.register_risk_policy_evidence_signing_key("signer", public)
    snapshot = repo.export_trust_registry_snapshot(private, "signer")
    _, wrong = keys()
    assert not verify_snapshot(snapshot, wrong)["valid"]
    snapshot["audit_events"].append({"action": "forged"})
    assert not verify_snapshot(snapshot, public)["valid"]


def test_export_requires_active_matching_registered_key(tmp_path):
    repo = Repository(tmp_path / "key.db")
    private, public = keys()
    repo.register_risk_policy_evidence_signing_key("signer", public)
    _, other = keys()
    repo.register_risk_policy_evidence_signing_key("other", other)
    try:
        repo.export_trust_registry_snapshot(private, "other")
    except ValueError as exc:
        assert "match" in str(exc)
    else:
        raise AssertionError("mismatched signer key accepted")
    repo.revoke_risk_policy_evidence_signing_key("signer", "admin", "retired")
    try:
        repo.export_trust_registry_snapshot(private, "signer")
    except ValueError as exc:
        assert "active" in str(exc) or "match" in str(exc)
    else:
        raise AssertionError("revoked signer accepted")
