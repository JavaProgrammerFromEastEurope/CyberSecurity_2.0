import base64
import copy
import hashlib
import json
from datetime import datetime, timezone, timedelta

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from cybersec.evidence_audit import verify_evidence_against_registry, verify_files
from cybersec.evidence_offline import canonical as evidence_canonical
from cybersec.trust_registry import create_snapshot, canonical as registry_canonical


def keypair():
    private = Ed25519PrivateKey.generate()
    raw_private = private.private_bytes(serialization.Encoding.Raw, serialization.PrivateFormat.Raw, serialization.NoEncryption())
    raw_public = private.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
    return private, base64.b64encode(raw_private).decode(), base64.b64encode(raw_public).decode()


def make_bundle(private, key_id, created_at):
    core = {
        "format": "cybersec-policy-evidence-bundle", "schema_version": 1,
        "manifest": {"evidence_id": 3, "evaluation_id": 2, "evidence_sha256": "placeholder",
                      "created_at": created_at},
        "evidence": {"snapshot": {"sample": "evidence"}},
        "verification": {"verification_method": "sha256-canonical-json"},
    }
    core["manifest"]["evidence_sha256"] = hashlib.sha256(evidence_canonical(core["evidence"]["snapshot"])).hexdigest()
    digest = hashlib.sha256(evidence_canonical(core)).hexdigest()
    core["manifest"]["bundle_sha256"] = digest
    return {**core, "signature": {"algorithm": "Ed25519", "key_id": key_id,
                                  "value": base64.b64encode(private.sign(digest.encode("ascii"))).decode()}}


def make_snapshot(registry_private_b64, registry_id, evidence_public, revoked_at=None):
    now = datetime.now(timezone.utc)
    keys = [{"key_id": "evidence-key", "algorithm": "Ed25519", "public_key": evidence_public,
             "created_by": "admin", "created_at": (now - timedelta(days=1)).isoformat().replace("+00:00", "Z"),
             "revoked": revoked_at is not None, "revoked_by": "admin" if revoked_at else None,
             "revoked_at": revoked_at, "revoked_reason": "retired" if revoked_at else None}]
    return create_snapshot(keys, [], registry_private_b64, registry_id, "auditor")


def test_trust_aware_audit_accepts_valid_bundle_and_snapshot():
    evidence_private, _, evidence_public = keypair()
    registry_private, registry_private_b64, registry_public = keypair()
    now = datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")
    bundle = make_bundle(evidence_private, "evidence-key", now)
    snapshot = make_snapshot(registry_private_b64, "registry-key", evidence_public)
    report = verify_evidence_against_registry(bundle, snapshot, registry_public)
    assert report["valid"] is True
    assert report["evidence_verification"]["signature_valid"] is True
    assert report["signer_trust"]["active_at_signing"] is True
    assert report["audit_continuity"]["valid"] is True


def test_bundle_signed_after_key_revocation_is_rejected():
    evidence_private, _, evidence_public = keypair()
    _, registry_private_b64, registry_public = keypair()
    now = datetime.now(timezone.utc)
    revoked_at = (now - timedelta(minutes=1)).isoformat().replace("+00:00", "Z")
    bundle = make_bundle(evidence_private, "evidence-key", now.isoformat().replace("+00:00", "Z"))
    snapshot = make_snapshot(registry_private_b64, "registry-key", evidence_public, revoked_at)
    report = verify_evidence_against_registry(bundle, snapshot, registry_public)
    assert report["evidence_verification"]["signature_valid"] is True
    assert report["signer_trust"]["active_at_signing"] is False
    assert report["valid"] is False


def test_registry_tampering_and_unknown_signer_fail():
    evidence_private, _, evidence_public = keypair()
    _, registry_private_b64, registry_public = keypair()
    now = datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")
    bundle = make_bundle(evidence_private, "missing-key", now)
    snapshot = make_snapshot(registry_private_b64, "registry-key", evidence_public)
    assert not verify_evidence_against_registry(bundle, snapshot, registry_public)["valid"]
    changed = copy.deepcopy(snapshot)
    changed["keys"][0]["public_key"] = "not-the-key"
    report = verify_evidence_against_registry(bundle, changed, registry_public)
    assert report["registry_verification"]["valid"] is False
    assert report["valid"] is False


def test_portable_audit_file_workflow(tmp_path):
    evidence_private, _, evidence_public = keypair()
    _, registry_private_b64, registry_public = keypair()
    now = datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")
    bundle = make_bundle(evidence_private, "evidence-key", now)
    snapshot = make_snapshot(registry_private_b64, "registry-key", evidence_public)
    bundle_path, snapshot_path, public_path = (tmp_path / "bundle.json", tmp_path / "registry.json", tmp_path / "registry.pub")
    bundle_path.write_text(json.dumps(bundle), encoding="utf-8")
    snapshot_path.write_text(json.dumps(snapshot), encoding="utf-8")
    public_path.write_text(registry_public, encoding="utf-8")
    assert verify_files(bundle_path, snapshot_path, public_path)["valid"] is True
