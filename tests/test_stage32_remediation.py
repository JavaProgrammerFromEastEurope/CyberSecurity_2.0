from __future__ import annotations

import json
import threading
from datetime import date, timedelta
from http.server import ThreadingHTTPServer
from urllib.error import HTTPError
from urllib.request import Request, urlopen

import pytest

from cybersec.api import make_handler
from cybersec.db import connect
from cybersec.dashboard import dashboard_bytes
from cybersec.repository import Repository

TOKEN = "stage32-remediation-test-token-long-enough"


def _finding(repo):
    repo.add_target("https://example.com", authorized=True)
    return repo.add_finding("https://example.com", "Example XSS", "High", "Firm", "xss")


def test_remediation_task_create_update_and_validation(tmp_path):
    repo = Repository(tmp_path / "remediation.db")
    finding = _finding(repo)
    task = repo.upsert_remediation_task(finding.id, status="in_progress", assignee="appsec", due_date=(date.today() + timedelta(days=3)).isoformat(), notes="Patch and retest")
    assert task["finding_id"] == finding.id
    assert task["status"] == "in_progress"
    assert task["assignee"] == "appsec"
    assert task["notes"] == "Patch and retest"
    updated = repo.upsert_remediation_task(finding.id, status="resolved")
    assert updated["id"] == task["id"]
    assert updated["status"] == "resolved"
    assert updated["assignee"] == "appsec"  # omitted fields are preserved
    with pytest.raises(ValueError, match="status must be"):
        repo.upsert_remediation_task(finding.id, status="done")
    with pytest.raises(ValueError, match="due_date"):
        repo.upsert_remediation_task(finding.id, due_date="tomorrow")
    with pytest.raises(ValueError, match="does not exist"):
        repo.upsert_remediation_task(999)


def test_remediation_overdue_filters_and_summary(tmp_path):
    repo = Repository(tmp_path / "overdue.db")
    finding = _finding(repo)
    overdue = repo.upsert_remediation_task(finding.id, due_date=(date.today() - timedelta(days=1)).isoformat())
    finding2 = repo.add_finding("https://example.com", "Other issue", "Medium", "Firm", "csrf")
    repo.upsert_remediation_task(finding2.id, status="resolved", due_date=(date.today() - timedelta(days=2)).isoformat())
    assert [x["id"] for x in repo.list_remediation_tasks(overdue_only=True)] == [overdue["id"]]
    summary = repo.remediation_summary()
    assert summary["total"] == 2
    assert summary["overdue"] == 1
    assert summary["by_status"]["resolved"] == 1


def test_remediation_api_auth_filters_and_dashboard(tmp_path):
    repo = Repository(tmp_path / "api-remediation.db")
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
        assert call("/api/v1/remediation", auth=False)[0] == 401
        status, task = call(f"/api/v1/findings/{finding.id}/remediation", "POST", {"status": "blocked", "assignee": "team"})
        assert status == 200 and task["status"] == "blocked"
        assert call("/api/v1/remediation?status=blocked")[1]["total"] == 1
        assert call("/api/v1/remediation?overdue=maybe")[0] == 400
        assert call("/api/v1/findings/999999/remediation", "POST", {"status": "open"})[0] == 404
        assert call("/api/v1/remediation/summary")[1]["total"] == 1
        document = call("/openapi.json", auth=False)[1]
        assert "/api/v1/remediation" in document["paths"]
        assert "/api/v1/findings/{finding_id}/remediation" in document["paths"]
    finally:
        server.shutdown(); server.server_close(); thread.join(timeout=2)

    html = dashboard_bytes().decode()
    assert 'data-tab="remediation"' in html
    assert "/api/v1/remediation" in html
    assert "save-remediation" in html
