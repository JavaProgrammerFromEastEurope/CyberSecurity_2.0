from __future__ import annotations

import json
import threading
import urllib.error
import urllib.request
from http.server import ThreadingHTTPServer

import pytest

from cybersec.api import API_VERSION, make_handler
from cybersec.repository import Repository


def test_rule_versions_and_rollback_are_append_only(tmp_path):
    repo = Repository(tmp_path / "versions.db")
    rule = repo.save_risk_intelligence_rule({"name": "Baseline", "config": {"window_days": 7}, "actor": "alice"})
    repo.save_risk_intelligence_rule({"id": rule["id"], "name": "Baseline", "config": {"window_days": 21}, "actor": "bob"})
    repo.set_risk_intelligence_rule_enabled(rule["id"], False, "carol")
    versions = repo.list_risk_intelligence_rule_versions(rule["id"])
    assert [item["version_number"] for item in versions["items"]] == [3, 2, 1]
    assert versions["items"][1]["snapshot"]["config"]["window_days"] == 21
    restored = repo.rollback_risk_intelligence_rule(rule["id"], 1, "dana")
    assert restored["config"]["window_days"] == 7
    assert restored["enabled"] is True
    assert restored["restored_from_version"] == 1
    assert restored["current_version"] == 4
    versions_after = repo.list_risk_intelligence_rule_versions(rule["id"])
    assert len(versions_after["items"]) == 4
    listing = repo.list_risk_intelligence_rules(include_audit=True)
    assert any(entry["action"] == "rolled_back" and entry["actor"] == "dana" for entry in listing["audit"])


def test_invalid_or_missing_version_is_rejected(tmp_path):
    repo = Repository(tmp_path / "versions.db")
    rule = repo.save_risk_intelligence_rule({"name": "Only", "config": {}})
    with pytest.raises(ValueError, match="positive integer"):
        repo.rollback_risk_intelligence_rule(rule["id"], 0)
    with pytest.raises(ValueError, match="does not exist"):
        repo.rollback_risk_intelligence_rule(rule["id"], 99)


def test_comparison_history_stores_summary_and_full_result(tmp_path):
    repo = Repository(tmp_path / "compare.db")
    a = repo.save_risk_intelligence_rule({"name": "A", "config": {}})
    b = repo.save_risk_intelligence_rule({"name": "B", "config": {"window_days": 30}})
    result = repo.compare_risk_intelligence_rules([a["id"], b["id"]], "analyst-7")
    assert result["id"] > 0
    assert result["created_by"] == "analyst-7"
    history = repo.list_risk_intelligence_comparison_history()
    assert history["total"] == 1
    assert history["items"][0]["rule_ids"] == [a["id"], b["id"]]
    detail = repo.get_risk_intelligence_comparison(result["id"])
    assert detail["result"]["compared"] == 2
    assert len(detail["result"]["results"]) == 2
    with pytest.raises(ValueError, match="does not exist"):
        repo.get_risk_intelligence_comparison(999)


def test_versions_rollback_and_comparison_history_api(tmp_path):
    token = "stage40-test-token-with-sufficient-length"
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
        assert call("/api/v1/risk/rules/1/versions", auth=False)[0] == 401
        _, a = call("/api/v1/risk/rules", "POST", {"name": "A", "config": {"window_days": 7}})
        _, b = call("/api/v1/risk/rules", "POST", {"name": "B", "config": {"window_days": 14}})
        call("/api/v1/risk/rules", "POST", {"id": a["id"], "name": "A", "config": {"window_days": 28}})
        status, versions = call(f"/api/v1/risk/rules/{a['id']}/versions")
        assert status == 200 and versions["total"] == 2
        status, rolled = call(f"/api/v1/risk/rules/{a['id']}/rollback", "POST", {"version_number": 1, "actor": "api-tester"})
        assert status == 200 and rolled["config"]["window_days"] == 7
        status, comparison = call(f"/api/v1/risk/rules/compare?ids={a['id']},{b['id']}&actor=api-tester")
        assert status == 200 and comparison["id"] > 0
        status, history = call("/api/v1/risk/comparison-history")
        assert status == 200 and history["total"] == 1
        status, detail = call(f"/api/v1/risk/comparison-history/{comparison['id']}")
        assert status == 200 and detail["result"]["compared"] == 2
        spec = call("/openapi.json", auth=False)[1]
        assert "/api/v1/risk/rules/{rule_id}/versions" in spec["paths"]
        assert "/api/v1/risk/comparison-history/{comparison_id}" in spec["paths"]
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=2)
