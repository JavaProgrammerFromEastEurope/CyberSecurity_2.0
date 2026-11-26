from cybersec.reports import render_html_report, write_html_report


def test_html_report_contains_summary_and_findings():
    html = render_html_report({
        "targets": [{"id": 1, "url": "https://example.test", "authorized": 1, "created_at": "today"}],
        "jobs": [{"id": 2, "tool": "demo", "status": "completed", "created_at": "today"}],
        "findings": [{"id": 3, "title": "SQL injection", "severity": "High", "confidence": "Firm",
                      "vuln_type": "sqli", "url": "https://example.test/login", "parameter": "username",
                      "evidence": "sample evidence", "recommendation": "Use parameterized queries.",
                      "source_tool": "manual", "created_at": "today"}],
    }, generated_at="fixed timestamp")
    assert "Cyber Security Assessment Report" in html
    assert "1 unique finding(s)" in html
    assert "SQL injection" in html
    assert "Use parameterized queries." in html
    assert "P2" in html
    assert "fixed timestamp" in html


def test_report_escapes_untrusted_html_and_does_not_load_remote_assets():
    html = render_html_report({
        "targets": [], "jobs": [],
        "findings": [{"id": 1, "title": '<script>alert("x")</script>', "severity": "Medium",
                      "confidence": "Unknown", "vuln_type": "test", "url": 'https://example.test/?q="<x>',
                      "evidence": '<img src=x onerror="alert(1)">', "recommendation": "<b>fix</b>",
                      "source_tool": "manual"}],
    })
    assert "<script>alert" not in html
    assert "&lt;script&gt;" in html
    assert "&lt;img src=x onerror=&quot;alert(1)&quot;&gt;" in html
    assert "<b>fix</b>" not in html
    assert "https://fonts.googleapis.com" not in html
    assert "<link rel=\"stylesheet\" href=\"http" not in html


def test_empty_report_and_write(tmp_path):
    html = render_html_report({"targets": [], "jobs": [], "findings": []})
    assert "No targets registered." in html
    assert "No scan jobs recorded." in html
    assert "No findings recorded." in html
    path = write_html_report({"targets": [], "jobs": [], "findings": []}, tmp_path / "reports" / "report.html")
    assert path.exists()
    assert path.read_text(encoding="utf-8").startswith("<!doctype html>")


def test_report_filters_target_job_severity_and_priority():
    from cybersec.reports import filter_report_data
    data = {
        "targets": [{"id": 1, "url": "https://one.test"}, {"id": 2, "url": "https://two.test"}],
        "jobs": [{"id": 10, "target_id": 1}, {"id": 20, "target_id": 2}],
        "findings": [
            {"id": 1, "target_id": 1, "job_id": 10, "severity": "High", "confidence": "Firm", "vuln_type": "sqli"},
            {"id": 2, "target_id": 1, "job_id": 10, "severity": "Low", "confidence": "Unknown", "vuln_type": "info"},
            {"id": 3, "target_id": 2, "job_id": 20, "severity": "Critical", "confidence": "Certain", "vuln_type": "rce"},
        ],
    }
    filtered = filter_report_data(data, target_id=1, job_id=10, severities=["High"], priorities=["P2"])
    assert [item["id"] for item in filtered["targets"]] == [1]
    assert [item["id"] for item in filtered["jobs"]] == [10]
    assert [item["id"] for item in filtered["findings"]] == [1]
    assert len(data["findings"]) == 3  # input is not mutated


def test_executive_profile_omits_sensitive_technical_evidence():
    html = render_html_report({
        "targets": [], "jobs": [{"id": 1, "tool": "demo", "status": "completed"}],
        "findings": [{"id": 1, "title": "Example issue", "severity": "High", "confidence": "Firm",
                      "vuln_type": "sqli", "evidence": "PRIVATE_REQUEST_BODY", "parameter": "password",
                      "recommendation": "Use parameterized queries.", "source_tool": "manual"}],
    }, profile="executive", project_name="Example Project", assessment_start="2026-01-01", assessment_end="2026-01-02")
    assert "Example Project" in html
    assert "2026-01-01" in html and "2026-01-02" in html
    assert "Use parameterized queries." in html
    assert "PRIVATE_REQUEST_BODY" not in html
    assert "Scan jobs" not in html
    assert "password" not in html  # technical parameter value is excluded


def test_invalid_report_profile_is_rejected():
    import pytest
    with pytest.raises(ValueError, match="profile"):
        render_html_report({"targets": [], "jobs": [], "findings": []}, profile="unknown")
