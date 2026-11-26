from cybersec.repository import Repository
from cybersec.risk_analytics import build_portfolio_report, build_risk_summary
from test_stage22_api import api_server


def test_risk_summary_prioritizes_findings_and_rolls_up_targets(tmp_path):
    repo = Repository(tmp_path / "risk-summary.db")
    one = repo.add_target("https://one.example", authorized=True)
    two = repo.add_target("https://two.example", authorized=True)
    repo.add_finding("https://one.example", "Critical issue", "Critical", "Certain", "SQL Injection")
    repo.add_finding("https://one.example", "Firm high", "High", "Firm", "XSS")
    repo.add_finding("https://two.example", "Medium issue", "Medium", "Firm", "TLS")

    result = build_risk_summary(repo)
    assert result["summary"]["target_count"] == 2
    assert result["summary"]["finding_count"] == 3
    assert result["summary"]["priority_counts"] == {"P1": 1, "P2": 1, "P3": 1, "P4": 0}
    assert result["top_risks"][0]["title"] == "Critical issue"
    assert result["top_risks"][0]["risk_score"] == 9.5
    assert result["top_risks"][0]["risk"]["taxonomy"] == "sql_injection"
    target = next(x for x in result["targets"] if x["target_id"] == one.id)
    assert target["finding_count"] == 2
    assert target["priority_counts"]["P1"] == 1
    assert any(x["target_id"] == two.id for x in result["targets"])


def test_portfolio_report_is_metadata_only_and_limit_is_validated(tmp_path):
    import pytest
    repo = Repository(tmp_path / "portfolio.db")
    repo.add_target("https://example.com", authorized=True)
    report = build_portfolio_report(repo)
    assert report["report_type"] == "multi_target_risk_portfolio"
    assert report["generated_from"] == "stored_local_metadata"
    assert "not CVSS" in " ".join(report["limitations"])
    with pytest.raises(ValueError):
        build_risk_summary(repo, limit=0)
    with pytest.raises(ValueError):
        build_portfolio_report(repo, limit=5001)


def test_risk_api_routes_are_protected_and_documented(api_server):
    import json
    from urllib.error import HTTPError
    from urllib.request import Request, urlopen

    def get(path, token="test-token-that-is-at-least-24-chars"):
        headers = {} if token is None else {"Authorization": "Bearer " + token}
        try:
            with urlopen(Request(api_server + path, headers=headers), timeout=2) as response:
                return response.status, json.loads(response.read())
        except HTTPError as exc:
            return exc.code, json.loads(exc.read())

    assert get("/api/v1/risk/summary")[0] == 200
    assert get("/api/v1/portfolio/report")[1]["report_type"] == "multi_target_risk_portfolio"
    assert get("/api/v1/risk/summary", token=None)[0] == 401
    assert get("/api/v1/risk/summary?limit=0")[0] == 400
    document = get("/openapi.json", token=None)[1]
    assert "/api/v1/risk/summary" in document["paths"]
    assert "/api/v1/portfolio/report" in document["paths"]


def test_dashboard_has_risk_tab_and_portfolio_export(api_server):
    from urllib.request import urlopen
    with urlopen(api_server + "/dashboard", timeout=2) as response:
        body = response.read().decode("utf-8")
    assert 'data-tab="risk"' in body
    assert "/api/v1/risk/summary" in body
    assert "/api/v1/portfolio/report" in body
    assert "Export portfolio JSON" in body
    assert "risk_priority" in body
