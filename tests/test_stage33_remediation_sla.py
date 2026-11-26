from __future__ import annotations

import json
import threading
from datetime import date, timedelta
from http.server import ThreadingHTTPServer
from urllib.error import HTTPError
from urllib.request import Request, urlopen

from cybersec.api import API_VERSION, make_handler
from cybersec.dashboard import dashboard_bytes
from cybersec.repository import Repository

TOKEN = "stage33-remediation-sla-test-token-long-enough"


def _finding(repo, severity="High"):
    repo.add_target("https://example.com", authorized=True)
    return repo.add_finding("https://example.com", f"Example {severity}", severity, "Firm", "xss")


def test_default_policies_and_update_validation(tmp_path):
    repo = Repository(tmp_path / "sla.db")
    policies = repo.remediation_sla_policies()
    assert {key: value["days"] for key, value in policies.items()} == {
        "Critical": 7, "High": 14, "Medium": 30, "Low": 90, "Info": 180
    }
    assert repo.set_remediation_sla_policy("High", 10)["days"] == 10
    for severity, days in [("unknown", 10), ("High", 0), ("Low", 3651), ("Info", True)]:
        try:
            repo.set_remediation_sla_policy(severity, days)
        except ValueError:
            pass
        else:
            raise AssertionError("invalid SLA policy accepted")


def test_sla_enrichment_and_audit_history(tmp_path):
    repo = Repository(tmp_path / "history.db")
    finding = _finding(repo, "Critical")
    task = repo.upsert_remediation_task(finding.id, status="open", assignee="team")
    repo.upsert_remediation_task(finding.id, status="in_progress", assignee="appsec")
    history = repo.remediation_history(task["id"])
    assert len(history) == 2
    assert history[0]["event_type"] == "updated"
    assert history[0]["old_status"] == "open"
    assert history[0]["new_status"] == "in_progress"
    row = repo.list_remediation_tasks()[0]
    assert row["sla_days"] == 7
    assert row["sla_due_date"] == (date.fromisoformat(row["created_at"][:10]) + timedelta(days=7)).isoformat()
    assert row["sla_status"] in {"within_sla", "due_soon", "breached"}
    assert repo.remediation_sla_summary()["total"] == 1


def test_sla_routes_require_auth_and_are_documented(tmp_path):
    repo = Repository(tmp_path / "api.db")
    finding = _finding(repo)
    server = ThreadingHTTPServer(("127.0.0.1", 0), make_handler(repo, TOKEN))
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    base = f"http://127.0.0.1:{server.server_port}"

    def call(path, method="GET", body=None, auth=True):
        headers = {"Content-Type": "application/json"}
        if auth:
            headers["Authorization"] = f"Bearer {TOKEN}"
        request = Request(base + path, data=json.dumps(body).encode() if body is not None else None, headers=headers, method=method)
        try:
            with urlopen(request, timeout=2) as response:
                return response.status, json.loads(response.read())
        except HTTPError as exc:
            return exc.code, json.loads(exc.read())

    try:
        assert API_VERSION == "2.33.0"
        assert call("/api/v1/remediation/sla", auth=False)[0] == 401
        assert call(f"/api/v1/findings/{finding.id}/remediation", "POST", {"status": "open"})[0] == 200
        status, policy = call("/api/v1/remediation/sla-policy", "POST", {"severity": "High", "days": 11})
        assert status == 200 and policy["days"] == 11
        assert call("/api/v1/remediation/history?task_id=1")[1]["total"] == 1
        assert call("/api/v1/remediation/sla")[1]["policies"]["High"]["days"] == 11
        assert call("/api/v1/remediation/sla-policy", "POST", {"severity": "High", "days": 0})[0] == 400
        spec = call("/openapi.json", auth=False)[1]
        assert "/api/v1/remediation/sla-policy" in spec["paths"]
    finally:
        server.shutdown(); server.server_close(); thread.join(timeout=2)

    html = dashboard_bytes().decode()
    assert "SLA status" in html
    assert "sla_due_date" in html
