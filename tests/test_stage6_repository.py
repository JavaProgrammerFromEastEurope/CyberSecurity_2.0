import json
from cybersec.repository import Repository


def test_taxonomy_aliases_deduplicate_across_tools(tmp_path):
    repo = Repository(tmp_path / "test.db")
    repo.add_target("https://example.com", True)
    first = repo.add_finding("https://example.com", "SQL injection", "Medium", "Tentative",
                             "SQL Injection", url="https://example.com/item?id=1", source_tool="zap")
    second = repo.add_finding("https://example.com", "Possible SQLi", "High", "Firm",
                              "sqli", url="https://example.com/item?id=1", source_tool="nuclei")
    assert first.id == second.id
    assert len(repo.list_findings()) == 1
    assert second.vuln_type == "sql_injection"
    assert second.severity == "High"
    assert set(second.source_tool.split(",")) == {"zap", "nuclei"}


def test_json_export_contains_explainable_risk_assessment(tmp_path):
    repo = Repository(tmp_path / "test.db")
    repo.add_target("https://example.com", True)
    repo.add_finding("https://example.com", "Example finding", "Critical", "Certain",
                     "Remote Code Execution")
    data = repo.export_data()
    assert data["schema_version"] == 4
    assessment = data["findings"][0]["risk_assessment"]
    assert assessment["priority"] == "P1"
    assert assessment["risk_score"] == 9.5
    assert "triage heuristic" in assessment["rationale"]
    json.dumps(data)
