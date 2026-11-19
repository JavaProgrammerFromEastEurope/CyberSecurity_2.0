"""Validation summaries for imported scanner artifacts and integrity manifests."""
from __future__ import annotations

import hashlib
import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


def validate_payload(payload: object, payload_format: str = "json") -> dict[str, Any]:
    """Return an explainable, non-throwing validation summary for scanner data."""
    issues: list[str] = []
    recognized = False
    finding_count = 0
    if payload_format != "json":
        issues.append("Payload is text; structural JSON validation and replay are unavailable.")
    elif isinstance(payload, list):
        recognized = True
        finding_count = sum(isinstance(item, dict) for item in payload)
        if finding_count != len(payload):
            issues.append(f"Array contains {len(payload) - finding_count} non-object item(s).")
    elif isinstance(payload, dict):
        if isinstance(payload.get("findings"), list):
            recognized = True
            values = payload["findings"]
            finding_count = sum(isinstance(item, dict) for item in values)
            if finding_count != len(values):
                issues.append(f"findings contains {len(values) - finding_count} non-object item(s).")
        elif any(key in payload for key in ("template-id", "templateID", "matched-at", "info")):
            recognized = True
            finding_count = 1
        elif isinstance(payload.get("site"), list):
            recognized = True
            for site in payload["site"]:
                if not isinstance(site, dict):
                    issues.append("ZAP site collection contains a non-object item.")
                    continue
                alerts = site.get("alerts", [])
                if not isinstance(alerts, list):
                    issues.append("ZAP site alerts field is not an array.")
                    continue
                for alert in alerts:
                    if not isinstance(alert, dict):
                        issues.append("ZAP alerts collection contains a non-object item.")
                        continue
                    instances = alert.get("instances")
                    if isinstance(instances, list):
                        finding_count += sum(isinstance(instance, dict) for instance in instances)
                        if any(not isinstance(instance, dict) for instance in instances):
                            issues.append("ZAP alert instances contains a non-object item.")
                    else:
                        finding_count += 1
        else:
            issues.append("JSON is valid, but its structure is not a supported scanner-result shape.")
    else:
        issues.append("Top-level JSON value must be an object or array.")
    return {
        "valid": not issues,
        "recognized_format": recognized,
        "payload_format": payload_format,
        "finding_candidates": finding_count,
        "issue_count": len(issues),
        "issues": issues,
    }


def build_export_manifest(export_path: str | Path, data: dict[str, Any]) -> dict[str, Any]:
    """Build a sidecar manifest for an already-written JSON export."""
    path = Path(export_path)
    raw = path.read_bytes()
    return {
        "manifest_version": 1,
        "file": path.name,
        "sha256": hashlib.sha256(raw).hexdigest(),
        "size_bytes": len(raw),
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "schema_version": data.get("schema_version"),
        "counts": {
            "targets": len(data.get("targets", [])),
            "jobs": len(data.get("jobs", [])),
            "findings": len(data.get("findings", [])),
            "scan_artifacts": len(data.get("scan_artifacts", [])),
        },
    }


def verify_export_manifest(export_path: str | Path, manifest_path: str | Path) -> dict[str, Any]:
    """Verify an export against a manifest, returning errors instead of raising for mismatch."""
    export_file, manifest_file = Path(export_path), Path(manifest_path)
    try:
        manifest = json.loads(manifest_file.read_text(encoding="utf-8"))
        raw = export_file.read_bytes()
    except (OSError, json.JSONDecodeError) as exc:
        return {"valid": False, "error": str(exc)}
    digest = hashlib.sha256(raw).hexdigest()
    checks = {
        "sha256_matches": digest == manifest.get("sha256"),
        "size_matches": len(raw) == manifest.get("size_bytes"),
        "filename_matches": export_file.name == manifest.get("file"),
    }
    return {"valid": all(checks.values()), "checks": checks, "actual_sha256": digest}
