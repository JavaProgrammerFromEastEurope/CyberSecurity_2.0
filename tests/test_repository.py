import pytest

from cybersec.repository import Repository


def test_target_job_and_finding_lifecycle(tmp_path):
    repo = Repository(tmp_path / "test.db")
    target = repo.add_target("https://example.com", authorized=True)
    assert target.authorized is True

    job = repo.create_job("https://example.com/", "demo")
    assert job.status == "queued"

    finding = repo.add_finding(
        target_url="https://example.com", title="Missing security header",
        severity="Low", confidence="Firm", vuln_type="security-header",
        recommendation="Set a suitable Content-Security-Policy header.",
    )
    assert finding.severity == "Low"
    assert repo.export_data()["findings"][0]["title"] == "Missing security header"


def test_job_requires_authorized_target(tmp_path):
    repo = Repository(tmp_path / "test.db")
    repo.add_target("https://example.com", authorized=False)
    with pytest.raises(PermissionError):
        repo.create_job("https://example.com", "demo")


def test_rejects_unknown_tool(tmp_path):
    repo = Repository(tmp_path / "test.db")
    repo.add_target("https://example.com", authorized=True)
    with pytest.raises(ValueError):
        repo.create_job("https://example.com", "unknown")


def test_duplicate_findings_merge_sources_evidence_and_confidence(tmp_path):
    repo = Repository(tmp_path / "dedupe.db")
    repo.add_target("https://example.com", authorized=True)
    first = repo.add_finding(
        target_url="https://example.com", title="Missing CSP", severity="Low",
        confidence="Tentative", vuln_type="Missing Security Header", url="https://EXAMPLE.com/",
        evidence="Observed by ZAP", source_tool="zap",
    )
    second = repo.add_finding(
        target_url="https://example.com", title="Content Security Policy missing", severity="Medium",
        confidence="Firm", vuln_type="missing-security-header", url="https://example.com",
        evidence="Observed by Nuclei", source_tool="nuclei",
    )
    findings = repo.list_findings()
    assert len(findings) == 1
    assert first.id == second.id
    assert second.severity == "Medium"
    assert second.confidence == "Firm"
    assert second.source_tool == "nuclei,zap"
    assert "Observed by ZAP" in (second.evidence or "")
    assert "Observed by Nuclei" in (second.evidence or "")


def test_distinct_parameter_remains_separate(tmp_path):
    repo = Repository(tmp_path / "parameters.db")
    repo.add_target("https://example.com", authorized=True)
    repo.add_finding(target_url="https://example.com", title="Issue A", severity="Low",
                     confidence="Tentative", vuln_type="xss", url="https://example.com/search", parameter="q")
    repo.add_finding(target_url="https://example.com", title="Issue B", severity="Low",
                     confidence="Tentative", vuln_type="xss", url="https://example.com/search", parameter="id")
    assert len(repo.list_findings()) == 2
