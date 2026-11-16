from __future__ import annotations

import json
import threading
from datetime import date, timedelta
from http.server import ThreadingHTTPServer
from urllib.error import HTTPError
from urllib.request import Request, urlopen

import pytest

from cybersec.api import API_VERSION, make_handler
from cybersec.db import connect
from cybersec.repository import Repository

TOKEN = "stage38-rule-test-token"


def test_config_validation_and_persistence(tmp_path):
    repo = Repository(tmp_path / "rules.db")
    assert repo.get_risk_intelligence_config()["window_days"] == 7
    saved = repo.set_risk_intelligence_config({"window_days": 14, "minimum_findings": 5, "growth_ratio": 2.0, "criticality_boost": False})
    assert saved["window_days"] == 14
    assert saved["minimum_findings"] == 5
    assert saved["growth_ratio"] == 2.0
    assert saved["criticality_boost"] is False
    with pytest.raises(ValueError):
        repo.set_risk_intelligence_config({"window_days": 0})
    with pytest.raises(ValueError):
        repo.set_risk_intelligence_config({"unexpected": True})
    with pytest.raises(ValueError):
        repo.set_risk_intelligence_config({"criticality_boost": "yes"})


def test_preview_uses_custom_rules_without_persisting_alerts(tmp_path):
    repo = Repository(tmp_path / "preview.db")
    url = "https://preview.example.test"
    repo.add_target(url, authorized=True)
    today = date.today()
    for i in range(2):
        finding = repo.add_finding(url, f"Finding {i}", "High", "Firm", f"type-{i}", url=f"{url}/{i}")
        with connect(repo.db_path) as db:
            db.execute("UPDATE normalized_findings SET created_at=? WHERE id=?", ((today - timedelta(days=1)).isoformat() + "T12:00:00Z", finding.id))
    preview = repo.refresh_risk_intelligence({"minimum_findings": 2, "window_days": 3, "growth_ratio": 1.5}, persist=False)
    assert preview["preview"] is True
    assert preview["total"] == 1
    assert preview["items"][0]["details"]["window_days"] == 3
    assert preview["items"][0]["details"]["priority"] in {"P1", "P2", "P3", "P4"}
    assert repo.list_risk_intelligence_alerts()["total"] == 0
    # The default saved threshold is unchanged by a preview.
    assert repo.get_risk_intelligence_config()["minimum_findings"] == 3


def test_alert_filters_and_deduplication(tmp_path):
    repo = Repository(tmp_path / "filters.db")
    url = "https://filter.example.test"
    repo.add_target(url, authorized=True)
    today = date.today()
    for i in range(3):
        finding = repo.add_finding(url, f"Finding {i}", "High", "Firm", f"type-{i}", url=f"{url}/{i}")
        with connect(repo.db_path) as db:
            db.execute("UPDATE normalized_findings SET created_at=? WHERE id=?", ((today - timedelta(days=1)).isoformat() + "T12:00:00Z", finding.id))
    first = repo.refresh_risk_intelligence()
    second = repo.refresh_risk_intelligence()
    assert first["total"] == second["total"] == 1
    filtered = repo.list_risk_intelligence_alerts(alert_type="target_finding_growth", priority="P3")
    assert filtered["total"] == 1
    assert repo.list_risk_intelligence_alerts(alert_type="recurring_finding")["total"] == 0
    with pytest.raises(ValueError):
        repo.list_risk_intelligence_alerts(priority="P0")


def test_config_preview_filters_api_auth_and_openapi(tmp_path):
    repo = Repository(tmp_path / "api.db")
    server = ThreadingHTTPServer(("127.0.0.1", 0), make_handler(repo, TOKEN))
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    base = f"http://127.0.0.1:{server.server_port}"

    def call(path, method="GET", body=None, auth=True):
        headers = {"Authorization": f"Bearer {TOKEN}"} if auth else {}
        payload = None
        if body is not None:
            payload = json.dumps(body).encode()
            headers["Content-Type"] = "application/json"
        try:
            with urlopen(Request(base + path, data=payload, headers=headers, method=method), timeout=3) as response:
                return response.status, json.loads(response.read())
        except HTTPError as exc:
            return exc.code, json.loads(exc.read())

    try:
        assert API_VERSION == "2.33.0"
        assert call("/api/v1/risk/config", auth=False)[0] == 401
        assert call("/api/v1/risk/config")[1]["window_days"] == 7
        assert call("/api/v1/risk/config", "POST", {"window_days": 10})[1]["window_days"] == 10
        assert call("/api/v1/risk/intelligence/preview?window_days=5")[1]["preview"] is True
        assert call("/api/v1/risk/alerts?priority=P0")[0] == 400
        spec = call("/openapi.json", auth=False)[1]
        assert "/api/v1/risk/config" in spec["paths"]
        assert "/api/v1/risk/intelligence/preview" in spec["paths"]
        with urlopen(base + "/dashboard", timeout=3) as response:
            dashboard = response.read().decode()
        assert "Preview rules (no save)" in dashboard
        assert "Apply alert filters" in dashboard
    finally:
        server.shutdown()
        thread.join(timeout=3)
        server.server_close()
