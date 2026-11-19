from __future__ import annotations

import json
import os
import threading
import urllib.error
import urllib.request

import pytest

from cybersec.repository import Repository
from http.server import ThreadingHTTPServer

from cybersec.api import API_VERSION, make_handler


def test_named_rule_sets_create_update_enable_audit_and_compare(tmp_path):
    repo = Repository(tmp_path / "rules.db")
    baseline = repo.save_risk_intelligence_rule({"name": "Baseline", "description": "Default review", "config": {}, "actor": "alice"})
    strict = repo.save_risk_intelligence_rule({"name": "Strict", "config": {"minimum_findings": 8, "window_days": 14}, "actor": "bob"})
    assert baseline["enabled"] is True
    assert strict["config"]["minimum_findings"] == 8
    updated = repo.set_risk_intelligence_rule_enabled(strict["id"], False, "carol")
    assert updated["enabled"] is False
    changed = repo.save_risk_intelligence_rule({"id": strict["id"], "name": "Strict", "config": {"growth_ratio": 2.5}, "actor": "dave"})
    assert changed["config"]["window_days"] == 14
    assert changed["config"]["growth_ratio"] == 2.5
    listing = repo.list_risk_intelligence_rules(include_audit=True)
    assert listing["total"] == 2
    assert {a["action"] for a in listing["audit"]} >= {"created", "disabled", "updated"}
    assert {a["actor"] for a in listing["audit"]} >= {"alice", "bob", "carol", "dave"}
    comparison = repo.compare_risk_intelligence_rules([baseline["id"], strict["id"]])
    assert comparison["compared"] == 2
    assert comparison["results"][1]["enabled"] is False  # updates preserve disabled state unless explicitly changed
    assert "does not save alerts" in comparison["note"]


def test_rule_validation_duplicate_names_and_comparison_bounds(tmp_path):
    repo = Repository(tmp_path / "rules.db")
    repo.save_risk_intelligence_rule({"name": "One", "config": {}})
    with pytest.raises(ValueError, match="already exists"):
        repo.save_risk_intelligence_rule({"name": "one", "config": {}})
    with pytest.raises(ValueError, match="window_days"):
        repo.save_risk_intelligence_rule({"name": "Bad", "config": {"window_days": 0}})
    with pytest.raises(ValueError, match="between 2 and 10"):
        repo.compare_risk_intelligence_rules([1])
    with pytest.raises(ValueError, match="does not exist"):
        repo.get_risk_intelligence_rule(999)


def test_rule_comparison_does_not_persist_alerts_or_change_global_config(tmp_path):
    repo = Repository(tmp_path / "rules.db")
    a = repo.save_risk_intelligence_rule({"name": "A", "config": {"window_days": 7}})
    b = repo.save_risk_intelligence_rule({"name": "B", "config": {"window_days": 30}})
    before = repo.get_risk_intelligence_config()
    result = repo.compare_risk_intelligence_rules([a["id"], b["id"]])
    after = repo.get_risk_intelligence_config()
    assert result["compared"] == 2
    assert before["window_days"] == after["window_days"]
    with __import__("cybersec.db", fromlist=["connect"]).connect(repo.db_path) as db:
        assert db.execute("SELECT COUNT(*) FROM risk_intelligence_alerts").fetchone()[0] == 0


def test_rule_api_auth_routes_and_openapi(tmp_path, monkeypatch):
    token = "stage39-test-token-with-sufficient-length"
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
        req = urllib.request.Request(base + path, data=data, headers=headers, method=method)
        try:
            with urllib.request.urlopen(req, timeout=3) as response:
                return response.status, json.loads(response.read())
        except urllib.error.HTTPError as exc:
            return exc.code, json.loads(exc.read())
    try:
        assert API_VERSION == "2.33.0"
        assert call("/api/v1/risk/rules", auth=False)[0] == 401
        status, one = call("/api/v1/risk/rules", "POST", {"name": "A", "config": {}, "actor": "tester"})
        assert status == 201 and one["name"] == "A"
        status, two = call("/api/v1/risk/rules", "POST", {"name": "B", "config": {"minimum_findings": 5}})
        assert status == 201
        status, listed = call("/api/v1/risk/rules?audit=true")
        assert status == 200 and listed["total"] == 2 and listed["audit"]
        status, compared = call(f"/api/v1/risk/rules/compare?ids={one['id']},{two['id']}")
        assert status == 200 and compared["compared"] == 2
        status, disabled = call(f"/api/v1/risk/rules/{one['id']}/enabled", "POST", {"enabled": False, "actor": "tester"})
        assert status == 200 and disabled["enabled"] is False
        spec = call("/openapi.json", auth=False)[1]
        assert "/api/v1/risk/rules/compare" in spec["paths"]
        with urllib.request.urlopen(base + "/dashboard", timeout=3) as response:
            dashboard = response.read().decode()
        assert "Save current settings as named rule" in dashboard
        assert "Compare rule sets" in dashboard
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=2)
