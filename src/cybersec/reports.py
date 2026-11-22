"""Self-contained, escaped HTML report generation."""
from __future__ import annotations

from collections import Counter
from datetime import datetime, timezone
from html import escape
from pathlib import Path
from typing import Any

from cybersec.risk import assess_risk

_SEVERITIES = ("Critical", "High", "Medium", "Low", "Info")


def _e(value: Any, *, fallback: str = "—") -> str:
    if value is None or value == "":
        value = fallback
    return escape(str(value), quote=True)


def filter_report_data(
    data: dict[str, Any], *, target_id: int | None = None, job_id: int | None = None,
    severities: list[str] | None = None, priorities: list[str] | None = None,
) -> dict[str, Any]:
    """Return a filtered copy of report data; never mutate repository-exported data."""
    targets = list(data.get("targets", []))
    jobs = list(data.get("jobs", []))
    findings = list(data.get("findings", []))
    if target_id is not None:
        targets = [item for item in targets if int(item.get("id", -1)) == target_id]
        jobs = [item for item in jobs if int(item.get("target_id", -1)) == target_id]
        findings = [item for item in findings if int(item.get("target_id", -1)) == target_id]
    if job_id is not None:
        jobs = [item for item in jobs if int(item.get("id", -1)) == job_id]
        job_target_ids = {int(item.get("target_id", -1)) for item in jobs}
        findings = [item for item in findings if item.get("job_id") == job_id]
        if target_id is None:
            targets = [item for item in targets if int(item.get("id", -1)) in job_target_ids]
    severity_set = {item.casefold() for item in (severities or [])}
    if severity_set:
        findings = [item for item in findings if str(item.get("severity", "Info")).casefold() in severity_set]
    priority_set = {item.upper() for item in (priorities or [])}
    if priority_set:
        kept = []
        for item in findings:
            assessment = item.get("risk_assessment")
            if not isinstance(assessment, dict):
                try:
                    assessment = assess_risk(str(item.get("severity", "Info")), str(item.get("confidence", "Unknown")), str(item.get("vuln_type", "unknown"))).to_dict()
                except ValueError:
                    assessment = {"priority": "P4"}
            if str(assessment.get("priority", "P4")).upper() in priority_set:
                kept.append(item)
        findings = kept
    return {**data, "targets": targets, "jobs": jobs, "findings": findings}


def render_html_report(
    data: dict[str, Any], *, generated_at: str | None = None, profile: str = "technical",
    project_name: str = "Cyber Security Assessment", assessment_start: str | None = None,
    assessment_end: str | None = None,
) -> str:
    """Render a self-contained HTML report with technical or executive detail."""
    if profile not in {"technical", "executive"}:
        raise ValueError("profile must be 'technical' or 'executive'")
    targets = data.get("targets", [])
    jobs = data.get("jobs", [])
    findings = data.get("findings", [])
    generated = generated_at or datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")

    counts = Counter(str(item.get("severity", "Info")) for item in findings)
    by_priority = Counter()
    assessed: list[tuple[dict[str, Any], dict[str, Any]]] = []
    for finding in findings:
        assessment = finding.get("risk_assessment")
        if not isinstance(assessment, dict):
            try:
                assessment = assess_risk(
                    str(finding.get("severity", "Info")),
                    str(finding.get("confidence", "Unknown")),
                    str(finding.get("vuln_type", "unknown")),
                ).to_dict()
            except ValueError:
                assessment = {"priority": "P4", "risk_score": 0.0, "rationale": "Risk score unavailable."}
        by_priority[str(assessment.get("priority", "P4"))] += 1
        assessed.append((finding, assessment))
    assessed.sort(key=lambda pair: (int(str(pair[1].get("priority", "P4"))[1:]) if str(pair[1].get("priority", "P4"))[:1] == "P" and str(pair[1].get("priority", "P4"))[1:].isdigit() else 4, -float(pair[1].get("risk_score", 0)), str(pair[0].get("title", "")).casefold()))

    target_rows = "".join(
        "<tr>" + f"<td>#{_e(t.get('id'))}</td><td>{_e(t.get('url'))}</td>"
        + f"<td>{'Authorized' if t.get('authorized') else 'Not acknowledged'}</td><td>{_e(t.get('created_at'))}</td></tr>"
        for t in targets
    ) or '<tr><td colspan="4" class="empty">No targets registered.</td></tr>'
    job_rows = "".join(
        "<tr>" + f"<td>#{_e(j.get('id'))}</td><td>{_e(j.get('tool'))}</td><td>{_e(j.get('status'))}</td>"
        + f"<td>{_e(j.get('created_at'))}</td><td>{_e(j.get('started_at'))}</td><td>{_e(j.get('finished_at'))}</td></tr>"
        for j in jobs
    ) or '<tr><td colspan="6" class="empty">No scan jobs recorded.</td></tr>'

    finding_cards: list[str] = []
    for finding, risk in assessed:
        severity = str(finding.get("severity", "Info"))
        if profile == "executive":
            finding_cards.append(f'''<article class="finding executive-finding">
              <div class="finding-top"><span class="severity sev-{_e(severity.lower())}">{_e(severity.upper())}</span>
              <span class="priority">{_e(risk.get("priority", "P4"))} · {_e(risk.get("risk_score", 0))}/10</span></div>
              <h3>{_e(finding.get("title"))}</h3>
              <p><strong>Recommended action:</strong> {_e(finding.get("recommendation"), fallback="Review and validate this finding.")}</p>
              <p class="muted">Confidence: {_e(finding.get("confidence"))} · Type: {_e(risk.get("taxonomy", finding.get("vuln_type")))}</p>
            </article>''')
            continue
        finding_cards.append(f'''<article class="finding">
          <div class="finding-top"><span class="severity sev-{_e(severity.lower())}">{_e(severity.upper())}</span>
          <span class="priority">{_e(risk.get("priority", "P4"))} · {_e(risk.get("risk_score", 0))}/10</span></div>
          <h3>#{_e(finding.get("id"))} — {_e(finding.get("title"))}</h3>
          <dl class="details">
            <dt>Type / taxonomy</dt><dd>{_e(risk.get("taxonomy", finding.get("vuln_type")))}</dd>
            <dt>Confidence</dt><dd>{_e(finding.get("confidence"))}</dd>
            <dt>URL</dt><dd class="wrap">{_e(finding.get("url"))}</dd>
            <dt>Parameter</dt><dd>{_e(finding.get("parameter"))}</dd>
            <dt>Source tool(s)</dt><dd>{_e(finding.get("source_tool"))}</dd>
            <dt>Source artifacts</dt><dd>{_e(", ".join("#" + str(x) for x in finding.get("source_artifact_ids", [])) or "Not linked")}</dd>
            <dt>Recorded</dt><dd>{_e(finding.get("created_at"))}</dd>
          </dl>
          <h4>Risk rationale</h4><p>{_e(risk.get("rationale", "Risk score unavailable."))}</p>
          <h4>Evidence</h4><pre>{_e(finding.get("evidence"), fallback="No evidence recorded.")}</pre>
          <h4>Recommended remediation</h4><pre>{_e(finding.get("recommendation"), fallback="No recommendation recorded.")}</pre>
        </article>''')
    finding_content = "\n".join(finding_cards) or '<p class="empty panel">No findings recorded.</p>'

    severity_cards = "".join(
        f'<div class="metric"><span>{_e(severity)}</span><strong>{counts.get(severity, 0)}</strong></div>'
        for severity in _SEVERITIES
    )
    priority_cards = "".join(
        f'<div class="metric"><span>{priority}</span><strong>{by_priority.get(priority, 0)}</strong></div>'
        for priority in ("P1", "P2", "P3", "P4")
    )

    # Build this section before interpolating the template. Python 3.11/3.12
    # reject backslash-escaped string literals inside f-string expressions.
    job_section = (
        '<section><h2>Scan jobs</h2><div class="table-wrap"><table><thead><tr>'
        '<th>ID</th><th>Tool</th><th>Status</th><th>Created</th><th>Started</th>'
        '<th>Finished</th></tr></thead><tbody>' + job_rows + '</tbody></table></div></section>'
    ) if profile == "technical" else ""

    return f'''<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1">
<meta name="referrer" content="no-referrer">
<title>{_e(project_name)} — Cyber Security Assessment Report</title>
<style>
:root{{--ink:#172033;--muted:#5c667a;--line:#dce2eb;--paper:#f5f7fb;--accent:#244f91}}
*{{box-sizing:border-box}}body{{margin:0;background:var(--paper);color:var(--ink);font:15px/1.55 system-ui,-apple-system,BlinkMacSystemFont,"Segoe UI",sans-serif}}
header{{background:#14233d;color:white;padding:38px max(22px,calc((100% - 1100px)/2))}}header h1{{margin:0 0 6px;font-size:clamp(26px,4vw,38px)}}header p{{margin:4px 0;color:#d8e3f5}}main{{max-width:1100px;margin:26px auto;padding:0 20px 48px}}
section{{margin:28px 0}}h2{{font-size:23px;margin:0 0 14px}}h3{{font-size:19px;margin:12px 0}}h4{{margin:16px 0 4px;font-size:14px}}.metrics{{display:grid;grid-template-columns:repeat(auto-fit,minmax(130px,1fr));gap:10px}}
.metric,.panel,.finding{{background:white;border:1px solid var(--line);border-radius:12px;padding:16px}}.metric span{{display:block;color:var(--muted);font-size:13px}}.metric strong{{font-size:28px}}.table-wrap{{overflow:auto;background:white;border:1px solid var(--line);border-radius:12px}}table{{border-collapse:collapse;width:100%;min-width:650px}}th,td{{padding:11px 13px;text-align:left;vertical-align:top;border-bottom:1px solid var(--line);overflow-wrap:anywhere}}th{{background:#eef2f8;font-size:13px}}.finding{{margin:14px 0;break-inside:avoid}}.finding-top{{display:flex;justify-content:space-between;gap:12px;align-items:center}}.severity,.priority{{font-size:12px;font-weight:750;border-radius:5px;padding:4px 8px;background:#eef2f8}}.sev-critical,.sev-high{{background:#fee2e2;color:#991b1b}}.sev-medium{{background:#ffedd5;color:#9a3412}}.sev-low{{background:#fef9c3;color:#854d0e}}.sev-info{{background:#e0f2fe;color:#075985}}.details{{display:grid;grid-template-columns:minmax(130px,190px) minmax(0,1fr);gap:5px 14px}}dt{{color:var(--muted)}}dd{{margin:0;overflow-wrap:anywhere}}.wrap{{overflow-wrap:anywhere}}pre{{white-space:pre-wrap;overflow-wrap:anywhere;word-break:break-word;background:#f6f8fb;border:1px solid var(--line);border-radius:8px;padding:12px;margin:5px 0}}.empty{{color:var(--muted);font-style:italic}}.muted{{color:var(--muted);font-size:13px}}footer{{border-top:1px solid var(--line);padding-top:18px;color:var(--muted);font-size:13px}}
@media(max-width:600px){{main{{padding:0 12px 30px}}.details{{grid-template-columns:1fr;gap:0}}dd{{margin-bottom:8px}}}}
@media print{{body{{background:white;font-size:11pt}}header{{padding:22px;background:#14233d!important;print-color-adjust:exact}}main{{max-width:none;margin:0;padding:12px}}.finding,.metric,.panel{{box-shadow:none}}a{{color:inherit}}section{{break-inside:avoid}}.finding{{break-inside:avoid}}}}
</style></head>
<body><header><h1>{_e(project_name)}</h1><p>{"Executive summary" if profile == "executive" else "Technical assessment report"} · Generated {_e(generated)}</p><p>{len(targets)} target(s) · {len(jobs)} job(s) · {len(findings)} unique finding(s)</p><p>Assessment window: {_e(assessment_start)} — {_e(assessment_end)}</p></header>
<main>
<section><h2>Executive summary</h2><div class="metrics">{severity_cards}</div>
<p>This report summarizes recorded scanner and manually entered findings. Severity reflects the source/analyst classification; confidence describes how strongly the result is supported.</p></section>
<section><h2>Priority overview</h2><div class="metrics">{priority_cards}</div><p class="panel">P1–P4 and the 0–10 risk score are internal triage heuristics, not CVSS scores and not proof of exploitability. Validate findings manually before making remediation or disclosure decisions.</p></section>
<section><h2>Assessment targets</h2><div class="table-wrap"><table><thead><tr><th>ID</th><th>Target URL</th><th>Authorization acknowledgement</th><th>Registered</th></tr></thead><tbody>{target_rows}</tbody></table></div></section>
{job_section}
<section><h2>{"Prioritized findings and recommended actions" if profile == "executive" else "Findings and remediation"}</h2>{finding_content}</section>
<footer><p>Generated locally by Cyber Security Orchestrator. This document may contain sensitive assessment details; store and share it only with authorized recipients.</p><p>Report generation does not independently verify authorization, vulnerability exploitability, or completeness of scanner coverage. P1–P4 and 0–10 scores are internal triage heuristics, not CVSS.</p></footer>
</main></body></html>'''


def write_html_report(
    data: dict[str, Any], output: str | Path, *, profile: str = "technical",
    project_name: str = "Cyber Security Assessment", assessment_start: str | None = None,
    assessment_end: str | None = None,
) -> Path:
    path = Path(output)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(render_html_report(data, profile=profile, project_name=project_name,
                                       assessment_start=assessment_start, assessment_end=assessment_end), encoding="utf-8")
    return path
