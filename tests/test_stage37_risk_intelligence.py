from __future__ import annotations

import json
import threading
from datetime import date, timedelta
from http.server import ThreadingHTTPServer
from urllib.error import HTTPError
from urllib.request import Request, urlopen

from cybersec.api import API_VERSION, make_handler
from cybersec.db import connect
from cybersec.repository import Repository

TOKEN = "stage37-risk-intelligence-test-token"


def test_growth_and_overdue_signals_are_explainable_and_persisted(tmp_path):
    repo = Repository(tmp_path / "intel.db")
    today = date.today()
    target_url = "https://growing.example.test"
    repo.add_target(target_url, authorized=True)
    for index in range(3):
        finding = repo.add_finding(target_url, f"Finding {index}", "High", "Firm", f"type-{index}",
                                   url=f"{target_url}/path-{index}")
        with connect(repo.db_path) as db:
            db.execute("UPDATE normalized_findings SET created_at=? WHERE id=?",
                       ((today - timedelta(days=2)).isoformat() + "T12:00:00Z", finding.id))
    finding = repo.list_findings()[0]
    task = repo.upsert_remediation_task(finding.id, status="in_progress", assignee="secops")
    with connect(repo.db_path) as db:
        db.execute("UPDATE remediation_tasks SET due_date=? WHERE id=?",
                   ((today - timedelta(days=1)).isoformat(), task["id"]))

    result = repo.refresh_risk_intelligence()
    types = {item["alert_type"] for item in result["items"]}
    assert "target_finding_growth" in types
    assert "sla_backlog" in types
    assert all(item["explanation"] and isinstance(item["details"], dict) for item in result["items"])
    assert repo.list_risk_intelligence_alerts(status="open")["total"] >= 2
    assert repo.refresh_risk_intelligence()["total"] == result["total"]


def test_recurrence_after_resolved_task_and_acknowledgement(tmp_path):
    repo = Repository(tmp_path / "recurrence.db")
    url = "https://repeat.example.test"
    repo.add_target(url, authorized=True)
    finding = repo.add_finding(url, "Repeated issue", "Critical", "Certain", "xss", url=url + "/page")
    task = repo.upsert_remediation_task(finding.id, status="in_progress", assignee="secops")
    repo.record_remediation_verification(task["id"], outcome="verified", evidence="fixed")
    repo.upsert_remediation_task(finding.id, status="resolved", assignee="secops")
    with connect(repo.db_path) as db:
        db.execute("UPDATE remediation_history SET changed_at=? WHERE task_id=? AND new_status='resolved'",
                   ((date.today() - timedelta(days=1)).isoformat() + "T00:00:00Z", task["id"]))
    # A repeated observation of the same normalized fingerprint is recorded, even though the finding row is deduplicated.
    repo.add_finding(url, "Repeated issue", "Critical", "Certain", "xss", url=url + "/page")
    report = repo.refresh_risk_intelligence()
    alert = next(item for item in report["items"] if item["alert_type"] == "recurring_finding")
    assert alert["details"]["finding_id"] == finding.id
    ack = repo.acknowledge_risk_intelligence_alert(alert["id"], "analyst-1")
    assert ack["status"] == "acknowledged"
    assert ack["acknowledged_by"] == "analyst-1"
    assert next(item for item in repo.refresh_risk_intelligence()["items"] if item["id"] == alert["id"])["status"] == "acknowledged"


def test_alert_validation_and_api_auth(tmp_path):
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
        assert call("/api/v1/risk/intelligence", auth=False)[0] == 401
        assert call("/api/v1/risk/intelligence")[0] == 200
        assert call("/api/v1/risk/alerts?status=invalid")[0] == 400
        assert call("/api/v1/risk/alerts/999/acknowledge", "POST", {"acknowledged_by": "analyst"})[0] == 400
        spec = call("/openapi.json", auth=False)[1]
        assert "/api/v1/risk/intelligence" in spec["paths"]
        with urlopen(base + "/dashboard", timeout=3) as response:
            dashboard = response.read().decode()
        assert "Refresh risk intelligence" in dashboard
        assert "/api/v1/risk/intelligence" in dashboard
    finally:
        server.shutdown()
        thread.join(timeout=3)
        server.server_close()
