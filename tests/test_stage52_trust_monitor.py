import base64
import hashlib
import json
from datetime import datetime, timezone, timedelta

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from cybersec.evidence_offline import canonical as evidence_canonical
from cybersec.trust_registry import create_snapshot
from cybersec.trust_monitor import compare_registry_snapshots, revalidate_bundle_files


def pair():
    private = Ed25519PrivateKey.generate()
    priv = base64.b64encode(private.private_bytes(serialization.Encoding.Raw, serialization.PrivateFormat.Raw, serialization.NoEncryption())).decode()
    pub = base64.b64encode(private.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)).decode()
    return private, priv, pub


def bundle(private, key_id="evidence-key", created_at=None):
    created_at = created_at or datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")
    core = {"format": "cybersec-policy-evidence-bundle", "schema_version": 1,
            "manifest": {"evidence_id": 1, "evaluation_id": 1, "created_at": created_at},
            "evidence": {"snapshot": {"finding": "demo"}},
            "verification": {"verification_method": "sha256-canonical-json"}}
    core["manifest"]["evidence_sha256"] = hashlib.sha256(evidence_canonical(core["evidence"]["snapshot"])).hexdigest()
    digest = hashlib.sha256(evidence_canonical(core)).hexdigest()
    core["manifest"]["bundle_sha256"] = digest
    return {**core, "signature": {"algorithm": "Ed25519", "key_id": key_id,
                                  "value": base64.b64encode(private.sign(digest.encode("ascii"))).decode()}}


def snapshot(registry_priv, registry_id, evidence_pub, revoked=False):
    now = datetime.now(timezone.utc)
    keys = [{"key_id": "evidence-key", "algorithm": "Ed25519", "public_key": evidence_pub,
             "created_by": "admin", "created_at": (now - timedelta(days=2)).isoformat().replace("+00:00", "Z"),
             "revoked": revoked, "revoked_by": "admin" if revoked else None,
             "revoked_at": (now - timedelta(minutes=20)).isoformat().replace("+00:00", "Z") if revoked else None,
             "revoked_reason": "retired" if revoked else None}]
    return create_snapshot(keys, [], registry_priv, registry_id, "auditor")


def test_snapshot_diff_reports_revocation():
    ev_private, _, ev_public = pair()
    _, reg_private, reg_public = pair()
    before = snapshot(reg_private, "registry", ev_public, False)
    after = snapshot(reg_private, "registry", ev_public, True)
    report = compare_registry_snapshots(before, after, reg_public)
    assert report["valid"] is True
    assert report["audit_history_monotonic"] is True
    assert any(row["change"] == "revoked" for row in report["changes"])


def test_snapshot_diff_rejects_tampered_snapshot():
    _, reg_private, reg_public = pair()
    _, _, ev_public = pair()
    before = snapshot(reg_private, "registry", ev_public, False)
    after = snapshot(reg_private, "registry", ev_public, True)
    after["keys"][0]["revoked"] = False
    report = compare_registry_snapshots(before, after, reg_public)
    assert report["valid"] is False


def test_revalidation_reports_trust_lost_after_revocation(tmp_path):
    ev_private, _, ev_public = pair()
    _, reg_private, reg_public = pair()
    now = datetime.now(timezone.utc)
    signed_at = (now - timedelta(minutes=10)).isoformat().replace("+00:00", "Z")
    bundle_path = tmp_path / "evidence"
    bundle_path.mkdir()
    (bundle_path / "bundle.json").write_text(json.dumps(bundle(ev_private, created_at=signed_at)), encoding="utf-8")
    active = snapshot(reg_private, "registry", ev_public, False)
    revoked = snapshot(reg_private, "registry", ev_public, True)
    pub_path = tmp_path / "registry.pub"
    pub_path.write_text(reg_public, encoding="utf-8")
    active_path = tmp_path / "active.json"
    revoked_path = tmp_path / "revoked.json"
    active_path.write_text(json.dumps(active), encoding="utf-8")
    revoked_path.write_text(json.dumps(revoked), encoding="utf-8")
    first = revalidate_bundle_files(bundle_path, active_path, pub_path)
    first_path = tmp_path / "report.json"
    first_path.write_text(json.dumps(first), encoding="utf-8")
    second = revalidate_bundle_files(bundle_path, revoked_path, pub_path, first_path)
    assert first["valid"] is True
    assert second["valid"] is False
    assert second["results"][0]["transition"] == "trust_lost"


def test_revalidation_ignores_non_bundle_json_and_fails_bad_snapshot(tmp_path):
    _, reg_private, reg_public = pair()
    _, _, ev_public = pair()
    bundle_dir = tmp_path / "evidence"
    bundle_dir.mkdir()
    (bundle_dir / "notes.json").write_text('{"hello":"world"}', encoding="utf-8")
    snap = snapshot(reg_private, "registry", ev_public)
    snap["created_by"] = "tampered"
    snap_path = tmp_path / "snapshot.json"
    pub_path = tmp_path / "registry.pub"
    snap_path.write_text(json.dumps(snap), encoding="utf-8")
    pub_path.write_text(reg_public, encoding="utf-8")
    report = revalidate_bundle_files(bundle_dir, snap_path, pub_path)
    assert report["valid"] is False
    assert report["results"] == []
