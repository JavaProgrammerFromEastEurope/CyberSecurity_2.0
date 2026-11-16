from __future__ import annotations

import json
import threading
from datetime import datetime, timezone
from http.server import ThreadingHTTPServer
from urllib.error import HTTPError
from urllib.request import Request, urlopen

import pytest

from cybersec.api import make_handler
from cybersec.contextual_risk import build_contextual_risk
from cybersec.repository import Repository

TOKEN = "stage31-contextual-risk-token-long-enough"


def test_contextual_risk_includes_criticality_age_reasons_and_priority(tmp_path):
    repo = Repository(tmp_path / "contextual.db")
    target = repo.add_target("https://example.com", authorized=True)
    repo.set_target_criticality(target.id, "critical")
    job = repo.create_job("https://example.com", "demo")
    repo.start_job(job.id)
    repo.finish_job(job.id)
    repo.add_finding("https://example.com", "Critical SQL issue", "Critical", "Certain", "SQL Injection")
    from cybersec.db import connect
    with connect(repo.db_path) as db:
        db.execute("UPDATE normalized_findings SET created_at = ?", ("2026-09-01T00:00:00Z",))
    data = build_contextual_risk(repo, now=datetime(2026, 10, 26, tzinfo=timezone.utc))
    assert data["summary"]["finding_count"] == 1
    item = data["top_risks"][0]
    assert item["target_criticality"] == "critical"
    assert item["contextual_risk_score"] == 10.0
    assert item["contextual_priority"] == "P1"
    assert any("business criticality" in reason for reason in item["risk_reasons"])
    assert any("days old" in reason for reason in item["risk_reasons"])
    assert any("not a live availability check" in reason for reason in item["risk_reasons"])
    assert "not CVSS" in " ".join(data["limitations"])


def test_criticality_validation_and_old_database_migration(tmp_path):
    repo = Repository(tmp_path / "criticality.db")
    target = repo.add_target("https://example.com", authorized=True)
    with pytest.raises(ValueError):
        repo.set_target_criticality(target.id, "urgent")
    updated = repo.set_target_criticality(target.id, "high")
    assert updated.criticality == "high"
    assert repo.get_target_by_id(target.id).criticality == "high"


def test_contextual_risk_api_requires_token_and_criticality_update_is_protected(tmp_path):
    repo = Repository(tmp_path / "api-contextual.db")
    target = repo.add_target("https://example.com", authorized=True)
    server = ThreadingHTTPServer(("127.0.0.1", 0), make_handler(repo, TOKEN))
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    base = f"http://127.0.0.1:{server.server_port}"

    def request(path, method="GET", body=None, auth=True):
        headers = {"Content-Type": "application/json"}
        if auth:
            headers["Authorization"] = f"Bearer {TOKEN}"
        req = Request(base + path, data=json.dumps(body).encode() if body is not None else None, headers=headers, method=method)
        try:
            with urlopen(req, timeout=2) as response:
                return response.status, json.loads(response.read())
        except HTTPError as exc:
            return exc.code, json.loads(exc.read())

    try:
        assert request("/api/v1/risk/contextual")[0] == 200
        assert request("/api/v1/risk/contextual", auth=False)[0] == 401
        status, result = request(f"/api/v1/targets/{target.id}/criticality", "POST", {"criticality": "high"})
        assert status == 200 and result["criticality"] == "high"
        assert request(f"/api/v1/targets/{target.id}/criticality", "POST", {"criticality": "urgent"})[0] == 400
        document = request("/openapi.json", auth=False)[1]
        assert "/api/v1/risk/contextual" in document["paths"]
        assert "/api/v1/targets/{target_id}/criticality" in document["paths"]
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=2)


def test_dashboard_has_contextual_risk_tab_and_criticality_control(tmp_path):
    from cybersec.dashboard import dashboard_bytes
    html = dashboard_bytes().decode()
    assert 'data-tab="contextual"' in html
    assert "/api/v1/risk/contextual" in html
    assert "/criticality" in html
    assert "risk_reasons" in html
