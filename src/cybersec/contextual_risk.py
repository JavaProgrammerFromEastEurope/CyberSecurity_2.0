"""Context-aware, explainable risk ranking using local stored metadata only."""
from __future__ import annotations

from collections import Counter
from datetime import datetime, timezone
from typing import Any

_CRITICALITY_BONUS = {"low": 0.0, "medium": 0.5, "high": 1.2, "critical": 2.0}

def _age_days(value: str, now: datetime) -> int | None:
    if not value:
        return None
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
        if parsed.tzinfo is None:
            parsed = parsed.replace(tzinfo=timezone.utc)
        return max(0, int((now - parsed.astimezone(timezone.utc)).total_seconds() // 86400))
    except (ValueError, TypeError):
        return None

def build_contextual_risk(repo, *, limit: int = 1000, now: datetime | None = None) -> dict[str, Any]:
    """Rank stored findings with target criticality, repeatability, assessment status and data age.

    Assessment status is only a historical scan-job signal; it is not a live availability probe.
    """
    if not 1 <= limit <= 5000:
        raise ValueError("Contextual risk limit must be between 1 and 5000.")
    now = now or datetime.now(timezone.utc)
    targets = {t.id: t for t in repo.list_targets()}
    jobs_by_target: dict[int, list[Any]] = {}
    for job in repo.list_jobs():
        jobs_by_target.setdefault(job.target_id, []).append(job)
    findings = [f.to_dict() for f in repo.list_findings()]
    identity_counts = Counter((int(f["target_id"]), str(f.get("url", "")).casefold(), str(f.get("vuln_type", "")).casefold(), str(f.get("parameter") or "").casefold()) for f in findings)
    latest_status: dict[int, str] = {}
    for target_id, jobs in jobs_by_target.items():
        jobs.sort(key=lambda j: (j.finished_at or j.created_at, j.id), reverse=True)
        latest_status[target_id] = jobs[0].status if jobs else "unknown"
    assessed = []
    factors_summary = Counter()
    for finding in findings:
        target_id = int(finding["target_id"])
        target = targets.get(target_id)
        criticality = getattr(target, "criticality", "medium") if target else "medium"
        base = float(repo.assess_finding_risk(finding)["risk_score"]) if hasattr(repo, "assess_finding_risk") else None
        if base is None:
            from cybersec.risk import assess_risk
            base = assess_risk(finding["severity"], finding["confidence"], finding["vuln_type"]).risk_score
        age = _age_days(str(finding.get("created_at", "")), now)
        repeat_count = identity_counts[(target_id, str(finding.get("url", "")).casefold(), str(finding.get("vuln_type", "")).casefold(), str(finding.get("parameter") or "").casefold())]
        bonus = _CRITICALITY_BONUS.get(criticality, 0.5)
        reasons = [f"Base severity/confidence score: {base:.2f}/10"]
        if bonus:
            reasons.append(f"Target business criticality is {criticality} (+{bonus:.1f})")
        if repeat_count > 1:
            bonus += min(1.0, 0.25 * (repeat_count - 1))
            reasons.append(f"Similar finding identity appears {repeat_count} times in stored records")
        if age is not None and age >= 30:
            bonus += 0.5
            reasons.append(f"Finding data is {age} days old; revalidation is recommended (+0.5)")
        elif age is not None and age >= 7:
            bonus += 0.2
            reasons.append(f"Finding data is {age} days old; consider revalidation (+0.2)")
        status = latest_status.get(target_id, "unknown")
        if status == "failed":
            reasons.append("Most recent recorded assessment failed; coverage may be incomplete")
        elif status == "completed":
            reasons.append("Most recent recorded assessment completed; this is not a live availability check")
        else:
            reasons.append(f"Latest recorded assessment status: {status}")
        score = round(min(10.0, base + bonus), 2)
        priority = "P1" if score >= 8 else "P2" if score >= 5 else "P3" if score >= 2 else "P4"
        item = {**finding, "target_url": target.url if target else "Unknown target", "base_risk_score": base,
                "contextual_risk_score": score, "contextual_priority": priority, "target_criticality": criticality,
                "finding_age_days": age, "repeatability_count": repeat_count, "latest_assessment_status": status,
                "risk_reasons": reasons}
        assessed.append(item); factors_summary[priority] += 1
    assessed.sort(key=lambda x: ({"P1":0,"P2":1,"P3":2,"P4":3}.get(x["contextual_priority"],9), -x["contextual_risk_score"], x["target_id"], x["id"]))
    return {"schema_version": 1, "summary": {"finding_count": len(assessed), "priority_counts": {p: factors_summary.get(p, 0) for p in ("P1","P2","P3","P4")}, "target_count": len(targets)},
            "top_risks": assessed[:limit], "criticality_levels": ["low", "medium", "high", "critical"],
            "limitations": ["Contextual scores are heuristic triage aids, not CVSS or proof of exploitability.", "Target criticality must be set by an analyst; the default is medium.", "No live availability probe is performed; last assessment status is only a stored job signal.", "Repeatability is based on currently stored normalized finding identities and may underrepresent resolved or deduplicated recurrence.", "Age indicates revalidation need, not evidence that a finding remains exploitable."]}
