"""Continuous trust monitoring and offline evidence revalidation."""
from __future__ import annotations

import json
from datetime import datetime
from pathlib import Path
from typing import Any

from cybersec.evidence_audit import verify_evidence_against_registry
from cybersec.trust_registry import verify_snapshot


def _parse_time(value: Any) -> datetime | None:
    if not isinstance(value, str) or not value:
        return None
    try:
        return datetime.fromisoformat(value.replace("Z", "+00:00"))
    except (ValueError, TypeError):
        return None


def compare_registry_snapshots(previous: dict, current: dict, trusted_public_key_b64: str) -> dict:
    """Compare two independently signed snapshots, trusting neither until both verify."""
    old_result = verify_snapshot(previous, trusted_public_key_b64)
    new_result = verify_snapshot(current, trusted_public_key_b64)
    if not old_result.get("valid") or not new_result.get("valid"):
        return {
            "report_type": "trust-registry-change-report",
            "valid": False,
            "previous_snapshot_valid": bool(old_result.get("valid")),
            "current_snapshot_valid": bool(new_result.get("valid")),
            "changes": [],
            "reason": "one_or_both_snapshots_failed_verification",
        }

    old_keys = {item.get("key_id"): item for item in previous.get("keys", [])
                if isinstance(item, dict) and isinstance(item.get("key_id"), str)}
    new_keys = {item.get("key_id"): item for item in current.get("keys", [])
                if isinstance(item, dict) and isinstance(item.get("key_id"), str)}
    changes: list[dict] = []
    for key_id in sorted(set(old_keys) | set(new_keys)):
        old, new = old_keys.get(key_id), new_keys.get(key_id)
        if old is None:
            changes.append({"key_id": key_id, "change": "added",
                            "new_revoked": bool(new.get("revoked"))})
            continue
        if new is None:
            changes.append({"key_id": key_id, "change": "removed",
                            "previous_revoked": bool(old.get("revoked"))})
            continue
        if old.get("public_key") != new.get("public_key") or old.get("algorithm") != new.get("algorithm"):
            changes.append({"key_id": key_id, "change": "key_material_changed"})
        old_revoked, new_revoked = bool(old.get("revoked")), bool(new.get("revoked"))
        if old_revoked != new_revoked:
            changes.append({"key_id": key_id,
                            "change": "revoked" if new_revoked else "revocation_state_reversed",
                            "previous_revoked": old_revoked, "current_revoked": new_revoked,
                            "revoked_at": new.get("revoked_at")})
        if old.get("created_at") != new.get("created_at"):
            changes.append({"key_id": key_id, "change": "registration_timestamp_changed"})
    old_events = {json.dumps(e, sort_keys=True, separators=(",", ":")) for e in previous.get("audit_events", [])}
    new_events = {json.dumps(e, sort_keys=True, separators=(",", ":")) for e in current.get("audit_events", [])}
    if not old_events.issubset(new_events):
        changes.append({"change": "audit_history_not_monotonic",
                        "events_missing_from_current": len(old_events - new_events)})
    return {
        "report_type": "trust-registry-change-report",
        "valid": True,
        "previous_snapshot_valid": True,
        "current_snapshot_valid": True,
        "previous_snapshot_sha256": old_result.get("snapshot_sha256"),
        "current_snapshot_sha256": new_result.get("snapshot_sha256"),
        "previous_created_at": previous.get("created_at"),
        "current_created_at": current.get("created_at"),
        "changes": changes,
        "audit_history_monotonic": old_events.issubset(new_events),
        "change_count": len(changes),
        "limitations": ["Comparison only covers data represented in the two signed snapshots.",
                        "A signature does not prove that a registry operator included every real-world event."],
    }


def revalidate_bundle_files(evidence_dir: str | Path, snapshot_path: str | Path,
                            registry_public_key_path: str | Path,
                            previous_report_path: str | Path | None = None) -> dict:
    """Revalidate JSON evidence bundles against the current signed registry snapshot."""
    directory = Path(evidence_dir)
    if not directory.is_dir():
        raise ValueError("evidence_dir must be an existing directory")
    snapshot = json.loads(Path(snapshot_path).read_text(encoding="utf-8"))
    public = Path(registry_public_key_path).read_text(encoding="utf-8").strip()
    registry_result = verify_snapshot(snapshot, public)
    if not registry_result.get("valid"):
        return {"report_type": "continuous-evidence-revalidation", "valid": False,
                "registry_verification": registry_result, "results": [],
                "reason": "trust_snapshot_verification_failed"}
    previous = None
    if previous_report_path:
        previous = json.loads(Path(previous_report_path).read_text(encoding="utf-8"))
        if previous.get("report_type") != "continuous-evidence-revalidation":
            raise ValueError("previous report has an unsupported report_type")
    previous_by_file = {}
    if previous:
        for row in previous.get("results", []):
            if isinstance(row, dict) and isinstance(row.get("file"), str):
                previous_by_file[row["file"]] = row
    rows = []
    for path in sorted(directory.glob("*.json")):
        try:
            bundle = json.loads(path.read_text(encoding="utf-8"))
            if not isinstance(bundle, dict) or bundle.get("format") != "cybersec-policy-evidence-bundle":
                continue
            audit = verify_evidence_against_registry(bundle, snapshot, public)
            old = previous_by_file.get(path.name)
            old_valid = old.get("valid") if old else None
            new_valid = bool(audit.get("valid"))
            if old is None:
                transition = "new"
            elif old_valid == new_valid:
                transition = "unchanged"
            elif new_valid:
                transition = "trust_restored"
            else:
                transition = "trust_lost"
            rows.append({"file": path.name, "bundle_sha256": audit.get("evidence_verification", {}).get("bundle_sha256")
                         if isinstance(audit.get("evidence_verification"), dict) else None,
                         "valid": new_valid, "transition": transition, "audit": audit})
        except (OSError, json.JSONDecodeError, ValueError) as exc:
            rows.append({"file": path.name, "valid": False, "transition": "validation_error",
                         "error": str(exc)})
    return {"report_type": "continuous-evidence-revalidation", "valid": all(row.get("valid") is True for row in rows),
            "generated_at": datetime.now().astimezone().isoformat(), "registry_snapshot_sha256": registry_result.get("snapshot_sha256"),
            "registry_verification": registry_result, "evidence_directory": str(directory),
            "bundle_count": len(rows), "valid_count": sum(row.get("valid") is True for row in rows),
            "invalid_count": sum(row.get("valid") is not True for row in rows), "results": rows,
            "limitations": ["Only top-level *.json files are examined.",
                            "Trust status is evaluated against the supplied snapshot, not later registry events.",
                            "A prior report is a comparison input, not an independently authenticated historical record."]}
