"""Offline, explainable risk triage and multi-target portfolio summaries."""
from __future__ import annotations

from collections import Counter
from dataclasses import asdict
from typing import Any

from cybersec.risk import assess_risk

_PRIORITY_ORDER = {"P1": 0, "P2": 1, "P3": 2, "P4": 3}
_SEVERITIES = ("Critical", "High", "Medium", "Low", "Info")
_PRIORITIES = ("P1", "P2", "P3", "P4")


def build_risk_summary(repo, *, limit: int = 1000) -> dict[str, Any]:
    """Score saved findings and summarize risk per target without scanning or network access."""
    if not 1 <= limit <= 5000:
        raise ValueError("Risk summary limit must be between 1 and 5000.")
    targets = {target.id: target for target in repo.list_targets()}
    findings = repo.list_findings()
    assessed: list[dict[str, Any]] = []
    by_target: dict[int, list[dict[str, Any]]] = {}
    for finding in findings:
        item = finding.to_dict()
        assessment = assess_risk(item["severity"], item["confidence"], item["vuln_type"]).to_dict()
        target = targets.get(item["target_id"])
        enriched = {**item, "risk": assessment, "risk_priority": assessment["priority"], "risk_score": assessment["risk_score"], "risk_taxonomy": assessment["taxonomy"], "target_url": target.url if target else "Unknown target"}
        assessed.append(enriched)
        by_target.setdefault(int(item["target_id"]), []).append(enriched)
    assessed.sort(key=lambda x: (_PRIORITY_ORDER.get(x["risk"]["priority"], 9), -x["risk"]["risk_score"], x["target_id"], x["id"]))
    priority_counts = Counter(item["risk"]["priority"] for item in assessed)
    severity_counts = Counter(item["severity"] for item in assessed)
    target_rows = []
    for target_id, target in sorted(targets.items()):
        rows = by_target.get(target_id, [])
        priorities = Counter(x["risk"]["priority"] for x in rows)
        top_score = max((x["risk"]["risk_score"] for x in rows), default=0.0)
        target_rows.append({
            "target_id": target_id, "target_url": target.url, "authorized": target.authorized,
            "finding_count": len(rows), "top_risk_score": top_score,
            "priority_counts": {key: priorities.get(key, 0) for key in _PRIORITIES},
            "severity_counts": {key: sum(x["severity"] == key for x in rows) for key in _SEVERITIES},
        })
    target_rows.sort(key=lambda x: (-x["priority_counts"]["P1"], -x["priority_counts"]["P2"], -x["top_risk_score"], x["target_id"]))
    return {
        "schema_version": 1,
        "summary": {
            "target_count": len(targets), "finding_count": len(assessed),
            "priority_counts": {key: priority_counts.get(key, 0) for key in _PRIORITIES},
            "severity_counts": {key: severity_counts.get(key, 0) for key in _SEVERITIES},
            "p1_p2_count": priority_counts.get("P1", 0) + priority_counts.get("P2", 0),
        },
        "targets": target_rows,
        "top_risks": assessed[:limit],
        "limitations": [
            "Risk scores are triage heuristics based on severity and confidence; they are not CVSS scores.",
            "Scores do not prove exploitability or business impact and should be reviewed by an analyst.",
            "The summary reflects currently stored normalized findings and does not initiate scans or network requests.",
        ],
    }


def build_portfolio_report(repo, *, limit: int = 1000) -> dict[str, Any]:
    """Produce a report across all registered targets using stored metadata only."""
    data = build_risk_summary(repo, limit=limit)
    data["report_type"] = "multi_target_risk_portfolio"
    data["generated_from"] = "stored_local_metadata"
    return data
