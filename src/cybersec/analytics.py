"""Offline analytics across saved scan comparison snapshots."""
from __future__ import annotations

import html
import json
from collections import Counter
from datetime import datetime
from typing import Any


def build_history_analytics(repo, *, target_id: int | None = None, limit: int = 1000,
                            since: str | None = None, until: str | None = None) -> dict[str, Any]:
    """Summarize stored comparisons only; this function never runs scanners or makes network calls."""
    if not 1 <= limit <= 1000:
        raise ValueError("Analytics limit must be between 1 and 1000.")
    for label, value in (("since", since), ("until", until)):
        if value:
            try:
                datetime.fromisoformat(value.replace("Z", "+00:00"))
            except ValueError as exc:
                raise ValueError(f"Invalid {label} date/time; use ISO 8601.") from exc
    entries = repo.list_comparisons(limit=limit)
    snapshots: list[dict[str, Any]] = []
    for entry in entries:
        saved = repo.get_comparison(int(entry["id"]))
        if not saved:
            continue
        result = saved["result"]
        comparison = result.get("comparison", {})
        before_job = comparison.get("before_job", {})
        after_job = comparison.get("after_job", {})
        current_target = after_job.get("target_id")
        if target_id is not None and current_target != target_id:
            continue
        created = str(saved.get("created_at", ""))
        if since and created and created < since:
            continue
        if until and created and created > until:
            continue
        snapshots.append({"id": saved["id"], "created_at": created,
                          "before_job_id": saved["before_job_id"], "after_job_id": saved["after_job_id"],
                          "target_id": current_target, "result": result})
    # Analyze chronologically; the same issue can be resolved and later reappear.
    snapshots.sort(key=lambda x: (x["created_at"], x["id"]))
    resolved_identities: set[str] = set()
    reappeared: list[dict[str, Any]] = []
    severity_counts: Counter[str] = Counter()
    trend: list[dict[str, Any]] = []
    totals: Counter[str] = Counter()
    for snap in snapshots:
        result = snap["result"]
        for bucket in ("added", "resolved", "unchanged", "changed"):
            totals[bucket] += len(result.get(bucket, []))
        for item in result.get("added", []):
            identity = str(item.get("identity", ""))
            if identity and identity in resolved_identities:
                reappeared.append({"identity": identity, "title": item.get("title", "Untitled finding"),
                                   "url": item.get("url", ""), "comparison_id": snap["id"],
                                   "after_job_id": snap["after_job_id"], "severity": item.get("severity", "Unknown")})
            if identity:
                resolved_identities.discard(identity)
        for item in result.get("resolved", []):
            identity = str(item.get("identity", ""))
            if identity:
                resolved_identities.add(identity)
        current = []
        current.extend(result.get("added", []))
        current.extend(result.get("unchanged", []))
        current.extend(x.get("after", {}) for x in result.get("changed", []))
        counts = Counter(str(item.get("severity", "Unknown")) for item in current)
        severity_counts.update(counts)
        trend.append({"comparison_id": snap["id"], "created_at": snap["created_at"],
                      "target_id": snap["target_id"], "before_job_id": snap["before_job_id"],
                      "after_job_id": snap["after_job_id"], "summary": result.get("summary", {}),
                      "current_severity_counts": dict(sorted(counts.items()))})
    return {"schema_version": 1, "filters": {"target_id": target_id, "limit": limit, "since": since, "until": until},
            "summary": {"comparisons_analyzed": len(snapshots), "added_events": totals["added"],
                        "resolved_events": totals["resolved"], "unchanged_events": totals["unchanged"],
                        "severity_change_events": totals["changed"], "reappeared_findings": len(reappeared),
                        "severity_observations": dict(sorted(severity_counts.items()))},
            "reappeared": reappeared, "trend": trend,
            "limitations": ["Analytics are based only on saved comparison snapshots in the selected window.",
                            "A finding absent from a later imported artifact is not proof of remediation.",
                            "Reappearance detection depends on stable comparison identity fingerprints."]}


def render_history_html(data: dict[str, Any], *, title: str = "Security Assessment History") -> str:
    """Render a self-contained HTML history report with escaped source-derived values."""
    summary = data.get("summary", {})
    metrics = [("Comparisons", summary.get("comparisons_analyzed", 0)),
               ("Added events", summary.get("added_events", 0)),
               ("Resolved events", summary.get("resolved_events", 0)),
               ("Severity changes", summary.get("severity_change_events", 0)),
               ("Reappeared", summary.get("reappeared_findings", 0))]
    metric_html = "".join(f"<div class='metric'><strong>{html.escape(str(v))}</strong><span>{html.escape(k)}</span></div>" for k, v in metrics)
    rows = []
    for item in data.get("trend", []):
        rows.append("<tr>" + "".join(f"<td>{html.escape(str(value))}</td>" for value in (
            item.get("comparison_id", ""), item.get("created_at", ""), item.get("target_id", ""),
            item.get("before_job_id", ""), item.get("after_job_id", ""),
            json.dumps(item.get("summary", {}), ensure_ascii=False, sort_keys=True),
            json.dumps(item.get("current_severity_counts", {}), ensure_ascii=False, sort_keys=True))) + "</tr>")
    repeat_rows = []
    for item in data.get("reappeared", []):
        repeat_rows.append("<tr>" + "".join(f"<td>{html.escape(str(value))}</td>" for value in (
            item.get("comparison_id", ""), item.get("after_job_id", ""), item.get("severity", "Unknown"),
            item.get("title", ""), item.get("url", ""))) + "</tr>")
    limitations = "".join(f"<li>{html.escape(str(x))}</li>" for x in data.get("limitations", []))
    return """<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>""" + html.escape(title) + """</title><style>body{font:16px system-ui,sans-serif;max-width:1200px;margin:2rem auto;padding:0 1rem;color:#202124}h1,h2{line-height:1.2}.metrics{display:flex;flex-wrap:wrap;gap:.75rem}.metric{border:1px solid #ddd;border-radius:8px;padding:1rem;min-width:120px;display:grid;gap:.35rem}.metric strong{font-size:1.6rem}.metric span{color:#555}table{border-collapse:collapse;width:100%;margin:1rem 0;font-size:.9rem}th,td{border:1px solid #ddd;padding:.55rem;text-align:left;overflow-wrap:anywhere}th{background:#f5f5f5}li{margin:.4rem 0}</style></head><body><h1>""" + html.escape(title) + """</h1>
<div class="metrics">""" + metric_html + """</div><h2>Comparison trend</h2><table><thead><tr><th>Comparison</th><th>Created</th><th>Target</th><th>Before job</th><th>After job</th><th>Change summary</th><th>Severity observations</th></tr></thead><tbody>""" + "".join(rows) + """</tbody></table>
<h2>Reappeared findings</h2><table><thead><tr><th>Comparison</th><th>After job</th><th>Severity</th><th>Title</th><th>URL</th></tr></thead><tbody>""" + "".join(repeat_rows) + """</tbody></table><h2>Limitations</h2><ul>""" + limitations + """</ul></body></html>"""
