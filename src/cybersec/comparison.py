"""Offline comparison of retained scan artifacts between two jobs."""
from __future__ import annotations

import json
from collections.abc import Mapping
from typing import Any


def _records(payload: str, payload_format: str) -> list[dict[str, Any]]:
    if payload_format != "json":
        return []
    try:
        data = json.loads(payload)
    except (TypeError, json.JSONDecodeError):
        return []
    candidates: list[dict[str, Any]] = []

    def walk(value: Any) -> None:
        if isinstance(value, list):
            for child in value:
                walk(child)
        elif isinstance(value, Mapping):
            # A finding-shaped record, rather than every arbitrary nested object.
            if any(k in value for k in ("template-id", "template_id", "pluginId", "alert", "vuln_type")) and any(
                k in value for k in ("matched-at", "matched_at", "url", "host", "instances", "risk", "severity", "info")
            ):
                if "instances" in value and isinstance(value["instances"], list):
                    for instance in value["instances"]:
                        if isinstance(instance, Mapping):
                            merged = dict(value)
                            merged.pop("instances", None)
                            merged.update(instance)
                            candidates.append(merged)
                else:
                    candidates.append(dict(value))
                return
            for key in ("findings", "results", "alerts", "site", "data"):
                if key in value:
                    walk(value[key])
            # Common ZAP export: site -> alerts -> instances.
            if "alerts" not in value and "instances" in value and any(k in value for k in ("alert", "pluginId")):
                walk({"alerts": [value]})
    walk(data)
    return candidates


def _value(record: Mapping[str, Any], *keys: str) -> str:
    for key in keys:
        value = record.get(key)
        if value is not None and not isinstance(value, (dict, list)) and str(value).strip():
            return str(value).strip()
    info = record.get("info")
    if isinstance(info, Mapping):
        for key in keys:
            value = info.get(key)
            if value is not None and not isinstance(value, (dict, list)) and str(value).strip():
                return str(value).strip()
    return ""


def _fingerprint(record: Mapping[str, Any]) -> str:
    # Stable identity prioritizes scanner-native identifiers, then URL and title.
    native_id = _value(record, "template-id", "template_id", "templateID", "pluginId", "alert", "id")
    url = _value(record, "matched-at", "matched_at", "url", "uri", "host", "target")
    title = _value(record, "name", "title", "alert", "vuln_type")
    parameter = _value(record, "parameter", "param")
    return "|".join(part.casefold().rstrip("/") for part in (native_id or title, url, parameter))


def _severity(record: Mapping[str, Any]) -> str:
    value = _value(record, "severity", "risk", "classification").casefold()
    mapping = {"critical": "Critical", "high": "High", "medium": "Medium", "moderate": "Medium",
               "low": "Low", "info": "Info", "informational": "Info", "0": "Info", "1": "Low",
               "2": "Medium", "3": "High", "4": "Critical"}
    return mapping.get(value, "Unknown")


def _job_artifacts(repo, job_id: int) -> tuple[dict, list[dict]]:
    job = repo.get_job(job_id)
    if job is None:
        raise ValueError(f"Job #{job_id} does not exist.")
    artifacts = repo.search_scan_artifacts(job_id=job_id)
    return {"id": job.id, "target_id": job.target_id, "tool": job.tool, "status": job.status}, artifacts


def compare_jobs(repo, before_job_id: int, after_job_id: int) -> dict[str, Any]:
    """Compare two jobs' retained raw artifacts without running scanners or network calls."""
    before_job, before_artifacts = _job_artifacts(repo, before_job_id)
    after_job, after_artifacts = _job_artifacts(repo, after_job_id)
    if before_job["target_id"] != after_job["target_id"]:
        raise ValueError("Jobs must belong to the same registered target to compare results.")

    def collect(artifacts: list[dict]) -> dict[str, dict[str, Any]]:
        records: dict[str, dict[str, Any]] = {}
        for artifact in artifacts:
            for record in _records(artifact["payload"], artifact["payload_format"]):
                key = _fingerprint(record)
                if key and key.strip("|"):
                    item = {"identity": key, "title": _value(record, "name", "title", "alert", "vuln_type") or "Untitled finding",
                            "url": _value(record, "matched-at", "matched_at", "url", "uri", "host", "target"),
                            "severity": _severity(record), "source_tool": artifact["source_tool"],
                            "artifact_id": artifact["id"]}
                    previous = records.get(key)
                    if previous is None or (previous["severity"] == "Unknown" and item["severity"] != "Unknown"):
                        records[key] = item
        return records

    before, after = collect(before_artifacts), collect(after_artifacts)
    added, resolved, unchanged, changed = [], [], [], []
    for key in sorted(set(before) | set(after)):
        old, new = before.get(key), after.get(key)
        if old is None:
            added.append(new)
        elif new is None:
            resolved.append(old)
        elif old["severity"] != new["severity"]:
            changed.append({"before": old, "after": new, "change": "severity_changed"})
        else:
            unchanged.append(new)
    return {"schema_version": 1, "comparison": {"before_job": before_job, "after_job": after_job,
            "basis": "retained raw artifacts", "network_requests": 0},
            "summary": {"added": len(added), "resolved": len(resolved), "unchanged": len(unchanged), "changed": len(changed),
                        "before_findings": len(before), "after_findings": len(after)},
            "added": added, "resolved": resolved, "unchanged": unchanged, "changed": changed,
            "limitations": ["Only recognized finding-shaped records in retained JSON artifacts are compared.",
                            "Identity depends on scanner identifiers, URLs, and titles; scanner format differences may affect matching.",
                            "A resolved item means absent from the newer imported artifact set, not proof that the issue is fixed."]}
