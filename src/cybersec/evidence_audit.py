"""Trust-aware offline validation linking evidence signatures to registry history."""
from __future__ import annotations

import json
from datetime import datetime
from pathlib import Path
from typing import Any

from cybersec.evidence_offline import verify_bundle
from cybersec.trust_registry import verify_snapshot


def _time(value: Any) -> datetime | None:
    if not isinstance(value, str) or not value:
        return None
    try:
        return datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return None


def _audit_consistency(keys: list[dict], events: list[dict]) -> dict:
    key_ids = {item.get("key_id") for item in keys if isinstance(item, dict)}
    unknown = sorted({str(event.get("key_id")) for event in events
                      if isinstance(event, dict) and event.get("key_id") not in key_ids})
    malformed = [i for i, event in enumerate(events)
                 if not isinstance(event, dict) or not event.get("key_id") or not event.get("action") or not event.get("actor")]
    return {"valid": not unknown and not malformed, "unknown_key_ids": unknown,
            "malformed_event_indices": malformed, "event_count": len(events)}


def verify_evidence_against_registry(bundle: dict, snapshot: dict, registry_public_key_b64: str) -> dict:
    """Verify both signatures and assess whether the bundle signer was trusted at signing time."""
    registry = verify_snapshot(snapshot, registry_public_key_b64)
    if not registry.get("valid"):
        return {"report_type": "trust-aware-evidence-audit", "valid": False,
                "registry_verification": registry, "evidence_verification": None,
                "signer_trust": {"valid": False, "reason": "registry_snapshot_not_trusted"},
                "audit_continuity": _audit_consistency(snapshot.get("keys", []), snapshot.get("audit_events", []))}
    if not isinstance(bundle, dict) or bundle.get("format") != "cybersec-policy-evidence-bundle":
        raise ValueError("Input is not a supported policy evidence bundle")
    signature = bundle.get("signature")
    if not isinstance(signature, dict) or signature.get("algorithm") != "Ed25519":
        evidence_result = verify_bundle(bundle, None)
        signer_result = {"valid": False, "reason": "evidence_bundle_must_use_ed25519"}
    else:
        signer_id = signature.get("key_id")
        signer = next((item for item in snapshot.get("keys", [])
                       if isinstance(item, dict) and item.get("key_id") == signer_id), None)
        if signer is None:
            evidence_result = verify_bundle(bundle, None)
            signer_result = {"valid": False, "key_id": signer_id, "reason": "signer_absent_from_registry_snapshot"}
        else:
            public_key = signer.get("public_key")
            evidence_result = verify_bundle(bundle, public_key if isinstance(public_key, str) else None)
            manifest = bundle.get("manifest", {})
            signed_at = _time(manifest.get("created_at")) if isinstance(manifest, dict) else None
            revoked_at = _time(signer.get("revoked_at"))
            time_known = signed_at is not None
            revoked_before_signing = bool(revoked_at and signed_at and revoked_at <= signed_at)
            active_at_signing = bool(time_known and not revoked_before_signing and
                                      (_time(signer.get("created_at")) is None or _time(signer.get("created_at")) <= signed_at))
            signer_result = {"valid": bool(evidence_result.get("valid") and active_at_signing),
                             "key_id": signer_id, "key_found": True,
                             "registered_public_key_used": True,
                             "signature_valid": evidence_result.get("signature_valid"),
                             "signed_at": manifest.get("created_at"), "key_created_at": signer.get("created_at"),
                             "key_revoked_at": signer.get("revoked_at"),
                             "active_at_signing": active_at_signing,
                             "reason": None if active_at_signing else ("signing_time_missing_or_invalid" if not time_known else "key_not_active_at_signing_time")}
    continuity = _audit_consistency(snapshot.get("keys", []), snapshot.get("audit_events", []))
    valid = bool(registry.get("valid") and evidence_result.get("valid") and signer_result.get("valid") and continuity.get("valid"))
    return {"report_type": "trust-aware-evidence-audit", "valid": valid,
            "registry_verification": registry, "evidence_verification": evidence_result,
            "signer_trust": signer_result, "audit_continuity": continuity,
            "limitations": ["The registry snapshot is evaluated as-of its creation; it cannot reveal later revocations.",
                            "Audit continuity here checks event references and required fields, not an external append-only log.",
                            "A valid signature proves possession of the corresponding private key, not the truth of evidence contents."]}


def verify_files(evidence_path: str | Path, snapshot_path: str | Path,
                 registry_public_key_path: str | Path) -> dict:
    bundle = json.loads(Path(evidence_path).read_text(encoding="utf-8"))
    snapshot = json.loads(Path(snapshot_path).read_text(encoding="utf-8"))
    public = Path(registry_public_key_path).read_text(encoding="utf-8").strip()
    return verify_evidence_against_registry(bundle, snapshot, public)
