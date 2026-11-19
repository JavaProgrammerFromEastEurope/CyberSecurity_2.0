"""Offline verification for portable evidence bundles and custody checkpoints.

This module deliberately does not initialize or connect to the project database.
Trust is established only by an explicitly supplied Ed25519 public key.
"""
from __future__ import annotations

import base64
import hashlib
import hmac
import json
from pathlib import Path

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey


def canonical(value: dict) -> bytes:
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode("utf-8")


def _decode_key(value: str) -> bytes:
    try:
        raw = base64.b64decode(value, validate=True)
    except Exception as exc:
        raise ValueError("public key must be valid base64") from exc
    if len(raw) != 32:
        raise ValueError("Ed25519 public key must decode to exactly 32 bytes")
    return raw


def verify_bundle(bundle: dict, trusted_public_key_b64: str | None = None) -> dict:
    if not isinstance(bundle, dict) or bundle.get("format") != "cybersec-policy-evidence-bundle" or bundle.get("schema_version") != 1:
        raise ValueError("Unsupported evidence bundle format or schema version")
    manifest, evidence, signature = bundle.get("manifest"), bundle.get("evidence"), bundle.get("signature")
    if not isinstance(manifest, dict) or not isinstance(evidence, dict) or not isinstance(signature, dict):
        raise ValueError("Bundle is missing manifest, evidence, or signature")
    snapshot = evidence.get("snapshot")
    if not isinstance(snapshot, dict):
        raise ValueError("Bundle evidence snapshot must be an object")
    evidence_digest = hashlib.sha256(canonical(snapshot)).hexdigest()
    evidence_ok = hmac.compare_digest(evidence_digest, str(manifest.get("evidence_sha256", "")))
    core = {k: v for k, v in bundle.items() if k != "signature"}
    core_manifest = dict(core.get("manifest", {}))
    expected_digest = core_manifest.pop("bundle_sha256", None)
    core["manifest"] = core_manifest
    actual_digest = hashlib.sha256(canonical(core)).hexdigest()
    bundle_ok = isinstance(expected_digest, str) and hmac.compare_digest(actual_digest, expected_digest)
    algorithm = signature.get("algorithm")
    signature_ok = None
    if algorithm == "Ed25519":
        if not trusted_public_key_b64:
            signature_ok = False
            signature_reason = "trusted_public_key_required"
        else:
            try:
                key = Ed25519PublicKey.from_public_bytes(_decode_key(trusted_public_key_b64))
                raw_signature = base64.b64decode(str(signature.get("value", "")), validate=True)
                key.verify(raw_signature, str(expected_digest).encode("ascii"))
                signature_ok = True
                signature_reason = None
            except Exception:
                signature_ok = False
                signature_reason = "invalid_signature_or_public_key"
    elif algorithm == "none" and signature.get("value") is None:
        signature_reason = "unsigned_integrity_only"
    elif algorithm == "HMAC-SHA256":
        signature_ok = False
        signature_reason = "hmac_requires_shared_secret_not_supported_by_offline_public_key_verifier"
    else:
        raise ValueError("Unsupported evidence bundle signature algorithm")
    valid = evidence_ok and bundle_ok and signature_ok is not False
    if algorithm == "Ed25519":
        valid = valid and signature_ok is True
    return {"valid": bool(valid), "evidence_integrity_valid": evidence_ok, "bundle_integrity_valid": bundle_ok,
            "signature_algorithm": algorithm, "signature_valid": signature_ok, "signature_reason": signature_reason,
            "key_id": signature.get("key_id"), "bundle_sha256": expected_digest,
            "trust_source": "explicit_external_public_key" if trusted_public_key_b64 else "none",
            "database_accessed": False}


def verify_checkpoint(checkpoint: dict, trusted_public_key_b64: str) -> dict:
    if not trusted_public_key_b64:
        raise ValueError("A trusted public key is required for checkpoint verification")
    if not isinstance(checkpoint, dict) or checkpoint.get("format") != "cybersec-custody-checkpoint" or checkpoint.get("schema_version") != 1:
        raise ValueError("Unsupported custody checkpoint format or schema version")
    fields = ("format", "schema_version", "checkpoint_id", "event_count", "head_hash", "key_id", "algorithm", "created_by", "created_at")
    if any(field not in checkpoint for field in fields) or checkpoint.get("algorithm") != "Ed25519":
        raise ValueError("Checkpoint is missing required fields or uses an unsupported algorithm")
    payload = {field: checkpoint[field] for field in fields}
    try:
        key = Ed25519PublicKey.from_public_bytes(_decode_key(trusted_public_key_b64))
        signature = base64.b64decode(checkpoint["signature_b64"], validate=True)
        key.verify(signature, canonical(payload))
    except Exception:
        return {"valid": False, "signature_valid": False, "reason": "invalid_signature_or_public_key", "database_accessed": False}
    try:
        count = int(checkpoint["event_count"])
    except (TypeError, ValueError) as exc:
        raise ValueError("event_count must be an integer") from exc
    if count < 0:
        raise ValueError("event_count must be non-negative")
    return {"valid": True, "signature_valid": True, "chain_prefix_valid": None,
            "event_count": count, "head_hash": checkpoint["head_hash"], "key_id": checkpoint["key_id"],
            "note": "Signature verified offline. Chain-prefix verification requires the exported custody events.",
            "database_accessed": False}


def verify_custody_events(checkpoint: dict, events: list[dict]) -> dict:
    """Verify an exported ordered event list against a checkpoint's signed prefix."""
    count = int(checkpoint.get("event_count", -1))
    if count < 0 or len(events) < count:
        return {"valid": False, "chain_prefix_valid": False, "reason": "insufficient_events", "checked_events": 0}
    previous_hash = None
    for index, event in enumerate(events[:count]):
        details = event.get("details")
        if details is None and isinstance(event.get("details_json"), str):
            details = json.loads(event["details_json"])
        payload = {"event_type": event["event_type"], "actor": event["actor"], "evidence_id": event.get("evidence_id"),
                   "evaluation_id": event.get("evaluation_id"), "bundle_sha256": event["bundle_sha256"], "details": details or {},
                   "previous_hash": previous_hash, "created_at": event["created_at"]}
        digest = hashlib.sha256(canonical(payload)).hexdigest()
        if event.get("previous_hash") != previous_hash or not hmac.compare_digest(digest, str(event.get("event_hash", ""))):
            return {"valid": False, "chain_prefix_valid": False, "reason": "event_hash_mismatch", "failed_event_index": index, "checked_events": index}
        previous_hash = event["event_hash"]
    expected_head = previous_hash if count else None
    ok = expected_head == checkpoint.get("head_hash")
    return {"valid": ok, "chain_prefix_valid": ok, "checked_events": count,
            "head_hash": expected_head, "reason": None if ok else "checkpoint_head_mismatch"}


def verify_file(path: str | Path, public_key_path: str | Path | None = None, custody_events_path: str | Path | None = None) -> dict:
    data = json.loads(Path(path).read_text(encoding="utf-8"))
    key = Path(public_key_path).read_text(encoding="utf-8").strip() if public_key_path else None
    if isinstance(data, dict) and data.get("format") == "cybersec-policy-evidence-bundle":
        if custody_events_path:
            raise ValueError("--custody-events is only valid with a custody checkpoint")
        return verify_bundle(data, key)
    if isinstance(data, dict) and data.get("format") == "cybersec-custody-checkpoint":
        if not key:
            raise ValueError("A trusted public-key file is required for checkpoint verification")
        result = verify_checkpoint(data, key)
        if custody_events_path:
            event_data = json.loads(Path(custody_events_path).read_text(encoding="utf-8"))
            events = event_data.get("events") if isinstance(event_data, dict) else event_data
            if not isinstance(events, list):
                raise ValueError("Custody events file must be a JSON array or an object with an events array")
            chain = verify_custody_events(data, events)
            result["chain_prefix_valid"] = chain["chain_prefix_valid"]
            result["checked_events"] = chain["checked_events"]
            result["chain_prefix_reason"] = chain.get("reason")
            result["valid"] = bool(result["valid"] and chain["valid"])
        return result
    raise ValueError("Input is not a supported evidence bundle or custody checkpoint")
