"""Safe, repeatable artifact import and replay helpers."""
from __future__ import annotations

import json
from pathlib import Path
from urllib.parse import urlsplit

from cybersec.repository import Repository


def import_artifact_file(repo: Repository, job_id: int, source_tool: str, path: str | Path, *, status: str = "complete") -> dict:
    """Import bytes as JSON when valid, otherwise preserve decoded text."""
    file_path = Path(path)
    raw = file_path.read_bytes()
    try:
        content = raw.decode("utf-8-sig")
    except UnicodeDecodeError:
        content = raw.decode("utf-8", errors="replace")
        status = "corrupt" if status == "complete" else status
    import_format = "json"
    try:
        payload: object = json.loads(content)
    except json.JSONDecodeError:
        # Support Nuclei-style JSONL files where each non-empty line is one JSON record.
        lines = [line for line in content.splitlines() if line.strip()]
        parsed_lines: list[object] = []
        jsonl_ok = bool(lines)
        if lines:
            for line in lines:
                try:
                    parsed_lines.append(json.loads(line))
                except json.JSONDecodeError:
                    jsonl_ok = False
                    break
        if jsonl_ok and all(isinstance(item, dict) for item in parsed_lines):
            payload = parsed_lines
            import_format = "jsonl"
        else:
            payload = content
            status = "corrupt" if status == "complete" else status
            import_format = "text"
    return repo.store_scan_artifact(
        job_id, source_tool, payload, status=status,
        metadata={"imported_from": file_path.name, "byte_length": len(raw), "ingestion": "file-import",
                  "source_format": import_format},
    )


def _items_from_payload(payload: object) -> list[dict]:
    if isinstance(payload, list):
        return [item for item in payload if isinstance(item, dict)]
    if not isinstance(payload, dict):
        return []
    findings = payload.get("findings")
    if isinstance(findings, list):
        return [item for item in findings if isinstance(item, dict)]
    # Common Nuclei JSONL-style records are imported as a single JSON object.
    if any(key in payload for key in ("template-id", "templateID", "matched-at", "info")):
        return [payload]
    # Common ZAP export: site -> alerts -> instances. Flatten alert instances conservatively.
    flattened: list[dict] = []
    sites = payload.get("site")
    if isinstance(sites, list):
        for site in sites:
            if not isinstance(site, dict):
                continue
            alerts = site.get("alerts", [])
            if not isinstance(alerts, list):
                continue
            for alert in alerts:
                if not isinstance(alert, dict):
                    continue
                instances = alert.get("instances") or [alert]
                for instance in instances if isinstance(instances, list) else []:
                    if isinstance(instance, dict):
                        flattened.append({**alert, **instance, "title": alert.get("name") or alert.get("alert") or alert.get("title"),
                                          "severity": alert.get("riskdesc", alert.get("severity", "Info")),
                                          "vuln_type": alert.get("alertRef", alert.get("pluginId", alert.get("name", "unknown"))),
                                          "solution": alert.get("solution"), "plugin_id": alert.get("pluginId")})
    return flattened


def replay_artifact(repo: Repository, artifact_id: int) -> dict:
    """Normalize supported findings from a stored artifact without making network calls."""
    artifact = repo.get_scan_artifact(artifact_id)
    if artifact is None:
        raise ValueError(f"Artifact #{artifact_id} does not exist.")
    if artifact["payload_format"] != "json":
        raise ValueError("Artifact payload is text, not JSON; it was preserved but cannot be replayed.")
    payload = json.loads(artifact["payload"])
    job = repo.get_job(artifact["job_id"])
    if job is None:
        raise ValueError("Artifact's scan job no longer exists.")
    target = repo.get_target_by_id(job.target_id)
    if target is None:
        raise ValueError("Artifact's target no longer exists.")
    target_parts = urlsplit(target.url)
    accepted = skipped = 0
    for item in _items_from_payload(payload):
        url = str(item.get("url") or item.get("matched-at") or item.get("matched_at") or item.get("uri") or target.url)
        parts = urlsplit(url)
        if (parts.scheme.lower(), (parts.hostname or "").lower(), parts.port) != (target_parts.scheme.lower(), (target_parts.hostname or "").lower(), target_parts.port):
            skipped += 1
            continue
        info = item.get("info") if isinstance(item.get("info"), dict) else {}
        raw_severity = str(item.get("severity") or info.get("severity") or "Info").split(" ")[0].title()
        severity = raw_severity if raw_severity in {"Critical", "High", "Medium", "Low", "Info"} else "Info"
        confidence_value = str(item.get("confidence") or "Unknown").title()
        confidence = confidence_value if confidence_value in {"Certain", "Firm", "Tentative", "Unknown"} else "Unknown"
        title = str(item.get("title") or item.get("name") or info.get("name") or item.get("template-id") or item.get("templateID") or "Imported scanner finding")
        vuln_type = str(item.get("vuln_type") or item.get("category") or item.get("type") or item.get("template-id") or item.get("templateID") or item.get("plugin_id") or item.get("alertRef") or title)
        source_id = str(item.get("id") or item.get("source_id") or item.get("alertRef") or "") or None
        template_id = str(item.get("template_id") or item.get("template-id") or item.get("templateID") or item.get("plugin_id") or "") or None
        evidence = item.get("evidence") or item.get("matched-line") or item.get("description") or item.get("desc")
        recommendation = item.get("solution") or item.get("recommendation") or info.get("remediation")
        repo.add_finding(target.url, title, severity, confidence, vuln_type, url=url,
                         parameter=item.get("parameter") or item.get("matched-parameter"),
                         evidence=str(evidence) if evidence is not None else None,
                         recommendation=str(recommendation) if recommendation is not None else None,
                         source_tool=artifact["source_tool"], job_id=job.id, source_id=source_id,
                         template_id=template_id, observed_at=str(item.get("timestamp") or item.get("observed_at") or "") or None)
        accepted += 1
    return {"artifact_id": artifact_id, "accepted": accepted, "skipped_out_of_scope": skipped}
