"""Portable, signed trust-registry snapshots and audit reports.

Private signing material is supplied at runtime and is never included in exports.
Offline verification trusts only an explicitly supplied Ed25519 public key.
"""
from __future__ import annotations
import base64, hashlib, hmac, json
from datetime import datetime, timezone
from pathlib import Path
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey


def canonical(value: dict) -> bytes:
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode("utf-8")


def _raw_b64(value: str, size: int, label: str) -> bytes:
    try: raw = base64.b64decode(value, validate=True)
    except Exception as exc: raise ValueError(f"{label} must be valid base64") from exc
    if len(raw) != size: raise ValueError(f"{label} must decode to exactly {size} bytes")
    return raw


def create_snapshot(keys: list[dict], audit_events: list[dict], signing_private_key_b64: str, signer_key_id: str, created_by: str = "security-auditor") -> dict:
    if not signer_key_id or len(signer_key_id) > 100: raise ValueError("signer_key_id must be 1..100 characters")
    if not created_by or len(created_by) > 200: raise ValueError("created_by must be 1..200 characters")
    private = Ed25519PrivateKey.from_private_bytes(_raw_b64(signing_private_key_b64, 32, "signing_private_key"))
    payload = {"format":"cybersec-trust-registry-snapshot", "schema_version":1,
               "created_at":datetime.now(timezone.utc).isoformat(timespec="seconds").replace("+00:00","Z"),
               "created_by":created_by, "signer_key_id":signer_key_id,
               "keys":sorted(keys, key=lambda x: x.get("key_id", "")),
               "audit_events":sorted(audit_events, key=lambda x: (x.get("id", 0), x.get("key_id", "")))}
    digest = hashlib.sha256(canonical(payload)).hexdigest()
    return {**payload, "snapshot_sha256":digest,
            "signature":{"algorithm":"Ed25519", "value":base64.b64encode(private.sign(digest.encode("ascii"))).decode("ascii")}}


def verify_snapshot(snapshot: dict, trusted_public_key_b64: str) -> dict:
    if not isinstance(snapshot, dict) or snapshot.get("format") != "cybersec-trust-registry-snapshot" or snapshot.get("schema_version") != 1:
        raise ValueError("Unsupported trust registry snapshot format or schema version")
    if not trusted_public_key_b64: raise ValueError("An explicitly trusted public key is required")
    required = ("created_at", "created_by", "signer_key_id", "keys", "audit_events", "snapshot_sha256", "signature")
    if any(k not in snapshot for k in required) or not isinstance(snapshot["keys"], list) or not isinstance(snapshot["audit_events"], list):
        raise ValueError("Snapshot is missing required fields or contains invalid collections")
    payload = {k:v for k,v in snapshot.items() if k not in {"snapshot_sha256", "signature"}}
    digest = hashlib.sha256(canonical(payload)).hexdigest()
    integrity = hmac.compare_digest(digest, str(snapshot.get("snapshot_sha256", "")))
    signature_valid = False
    if not isinstance(snapshot["signature"], dict) or snapshot["signature"].get("algorithm") != "Ed25519":
        return {"valid":False, "snapshot_integrity_valid":integrity, "signature_valid":False, "reason":"unsupported_signature_algorithm", "trust_source":"explicit_external_public_key", "database_accessed":False}
    try:
        public = Ed25519PublicKey.from_public_bytes(_raw_b64(trusted_public_key_b64, 32, "trusted_public_key"))
        sig = _raw_b64(snapshot["signature"].get("value", ""), 64, "signature")
        public.verify(sig, digest.encode("ascii")); signature_valid = True
    except Exception:
        signature_valid = False
    return {"valid":bool(integrity and signature_valid), "snapshot_integrity_valid":integrity,
            "signature_valid":signature_valid, "signature_algorithm":snapshot["signature"].get("algorithm"),
            "signer_key_id":snapshot["signer_key_id"], "key_count":len(snapshot["keys"]),
            "audit_event_count":len(snapshot["audit_events"]), "snapshot_sha256":digest,
            "trust_source":"explicit_external_public_key", "private_key_exported":False, "database_accessed":False}


def verify_file(path: str | Path, public_key_path: str | Path) -> dict:
    snapshot = json.loads(Path(path).read_text(encoding="utf-8"))
    public_key = Path(public_key_path).read_text(encoding="utf-8").strip()
    result = verify_snapshot(snapshot, public_key)
    return {"report_type":"portable-trust-registry-audit", "verification":result,
            "key_history":snapshot.get("keys", []), "audit_events":snapshot.get("audit_events", [])}
