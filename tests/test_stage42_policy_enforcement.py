import pytest

from cybersec.repository import Repository


def make_rule(repo, name="Policy rule", config=None):
    return repo.save_risk_intelligence_rule({
        "name": name,
        "description": "stage 42 test",
        "config": config or {"minimum_findings": 2},
        "actor": "author",
    })


def test_policy_status_excludes_unapproved_and_accepts_current_approval(tmp_path):
    repo = Repository(tmp_path / "policy.db")
    first = make_rule(repo, "approved")
    second = make_rule(repo, "unapproved")
    assert repo.get_risk_intelligence_policy_status()["eligible"] == 0
    repo.approve_risk_intelligence_rule(first["id"], "reviewer")
    status = repo.get_risk_intelligence_policy_status()
    by_id = {item["rule_id"]: item for item in status["items"]}
    assert by_id[first["id"]]["status"] == "compliant"
    assert by_id[first["id"]]["eligible_for_policy_evaluation"] is True
    assert by_id[second["id"]]["status"] == "unapproved"
    assert status["eligible"] == 1


def test_policy_status_detects_stale_approval_after_rule_change(tmp_path):
    repo = Repository(tmp_path / "stale.db")
    rule = make_rule(repo)
    repo.approve_risk_intelligence_rule(rule["id"], "reviewer", lock=False)
    repo.save_risk_intelligence_rule({"id": rule["id"], "name": rule["name"], "description": "changed", "config": {}, "actor": "editor"})
    item = repo.get_risk_intelligence_policy_status()["items"][0]
    assert item["status"] == "approval_stale"
    assert item["eligible_for_policy_evaluation"] is False


def test_policy_evaluation_is_preview_only_and_persists_history(tmp_path):
    repo = Repository(tmp_path / "evaluation.db")
    rule = make_rule(repo)
    repo.approve_risk_intelligence_rule(rule["id"], "reviewer")
    before = repo.get_risk_intelligence_summary(limit=100) if hasattr(repo, "get_risk_intelligence_summary") else None
    result = repo.evaluate_risk_intelligence_policy("policy-test")
    assert result["summary"]["rules_evaluated"] == 1
    assert result["summary"]["rules_excluded"] == 0
    assert "no alerts are persisted" in result["note"]
    history = repo.list_risk_intelligence_policy_evaluations()
    assert history["total"] == 1
    detail = repo.get_risk_intelligence_policy_evaluation(result["id"])
    assert detail["evaluated_by"] == "policy-test"
    assert detail["result"]["summary"]["rules_evaluated"] == 1


def test_policy_evaluation_excludes_unapproved_rules(tmp_path):
    repo = Repository(tmp_path / "excluded.db")
    make_rule(repo)
    result = repo.evaluate_risk_intelligence_policy()
    assert result["summary"]["rules_evaluated"] == 0
    assert result["summary"]["rules_excluded"] == 1
    assert result["excluded_rules"][0]["status"] == "unapproved"


def test_policy_history_limit_validation(tmp_path):
    repo = Repository(tmp_path / "limit.db")
    with pytest.raises(ValueError, match="limit"):
        repo.list_risk_intelligence_policy_evaluations(0)


def test_policy_api_routes_are_protected_and_documented(tmp_path):
    import json
    import threading
    import urllib.error
    import urllib.request
    from http.server import ThreadingHTTPServer

    from cybersec.api import API_VERSION, make_handler

    token = "stage42-policy-test-token"
    repo = Repository(tmp_path / "api.db")
    server = ThreadingHTTPServer(("127.0.0.1", 0), make_handler(repo, token))
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    base = f"http://127.0.0.1:{server.server_address[1]}"

    def call(path, method="GET", payload=None, auth=True):
        data = json.dumps(payload).encode() if payload is not None else None
        headers = {"Content-Type": "application/json"}
        if auth:
            headers["Authorization"] = "Bearer " + token
        request = urllib.request.Request(base + path, data=data, headers=headers, method=method)
        try:
            with urllib.request.urlopen(request, timeout=3) as response:
                return response.status, json.loads(response.read())
        except urllib.error.HTTPError as exc:
            return exc.code, json.loads(exc.read())

    try:
        assert API_VERSION == "2.33.0"
        assert call("/api/v1/risk/policy/status", auth=False)[0] == 401
        _, rule = call("/api/v1/risk/rules", "POST", {"name": "API governed", "config": {}})
        call(f"/api/v1/risk/rules/{rule['id']}/approve", "POST", {"actor": "reviewer"})
        status, evaluated = call("/api/v1/risk/policy/evaluate", "POST", {"actor": "api-test"})
        assert status == 200 and evaluated["summary"]["rules_evaluated"] == 1
        status, history = call("/api/v1/risk/policy/evaluations")
        assert status == 200 and history["total"] == 1
        status, detail = call(f"/api/v1/risk/policy/evaluations/{evaluated['id']}")
        assert status == 200 and detail["evaluated_by"] == "api-test"
        spec = call("/openapi.json", auth=False)[1]
        assert "/api/v1/risk/policy/status" in spec["paths"]
        assert "/api/v1/risk/policy/evaluate" in spec["paths"]
    finally:
        server.shutdown()
        thread.join(timeout=3)
        server.server_close()
