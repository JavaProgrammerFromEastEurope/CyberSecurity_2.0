import json

import pytest

from cybersec.analytics import build_history_analytics, render_history_html
from cybersec.cli import build_parser
from cybersec.comparison import compare_jobs
from cybersec.repository import Repository


def add_job(repo, target, findings):
    job = repo.create_job(target, "nuclei")
    repo.store_scan_artifact(job.id, "nuclei", {"findings": findings})
    return job


def record(repo, before, after):
    return repo.save_comparison(compare_jobs(repo, before.id, after.id))


def finding(template, url, title=None, severity="high"):
    return {"template-id": template, "title": title or template, "url": url, "severity": severity}


def test_analytics_detects_reappearing_findings(tmp_path):
    repo = Repository(tmp_path / "analytics.db")
    target = "https://example.com"
    repo.add_target(target, authorized=True)
    old = add_job(repo, target, [finding("xss", target + "/a")])
    empty = add_job(repo, target, [])
    record(repo, old, empty)  # resolved
    empty2 = add_job(repo, target, [])
    newer = add_job(repo, target, [finding("xss", target + "/a", severity="critical")])
    record(repo, empty2, newer)  # added again

    data = build_history_analytics(repo)
    assert data["summary"]["comparisons_analyzed"] == 2
    assert data["summary"]["resolved_events"] == 1
    assert data["summary"]["reappeared_findings"] == 1
    assert data["reappeared"][0]["severity"] == "Critical"
    assert data["trend"][-1]["after_job_id"] == newer.id


def test_analytics_filters_target_and_validates_limit_and_dates(tmp_path):
    repo = Repository(tmp_path / "analytics.db")
    target = "https://example.com"
    repo.add_target(target, authorized=True)
    before = add_job(repo, target, [])
    after = add_job(repo, target, [finding("x", target + "/x")])
    record(repo, before, after)
    assert build_history_analytics(repo, target_id=999)["summary"]["comparisons_analyzed"] == 0
    with pytest.raises(ValueError, match="between 1 and 1000"):
        build_history_analytics(repo, limit=0)
    with pytest.raises(ValueError, match="ISO 8601"):
        build_history_analytics(repo, since="not-a-date")


def test_html_escapes_untrusted_titles_and_contains_history(tmp_path):
    data = {"summary": {"comparisons_analyzed": 1, "added_events": 0, "resolved_events": 0,
                        "severity_change_events": 0, "reappeared_findings": 1},
            "trend": [{"comparison_id": 1, "created_at": "today", "target_id": 1,
                       "before_job_id": 2, "after_job_id": 3, "summary": {}, "current_severity_counts": {}}],
            "reappeared": [{"comparison_id": 1, "after_job_id": 3, "severity": "High",
                            "title": "<script>alert(1)</script>", "url": "https://example.com/?x=1&y=2"}],
            "limitations": ["Only saved history is included."]}
    rendered = render_history_html(data, title="History <report>")
    assert "&lt;script&gt;alert(1)&lt;/script&gt;" in rendered
    assert "<script>alert(1)</script>" not in rendered
    assert "History &lt;report&gt;" in rendered
    assert "Reappeared findings" in rendered


def test_cli_parser_accepts_analytics_commands():
    args = build_parser().parse_args(["job", "analytics", "--target-id", "2", "--since", "2026-01-01", "--output", "a.json"])
    assert args.job_command == "analytics" and args.target_id == 2 and args.output == "a.json"
    args = build_parser().parse_args(["report", "history-html", "--limit", "50", "--output", "history.html"])
    assert args.report_command == "history-html" and args.limit == 50
