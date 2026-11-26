from __future__ import annotations

import csv
import io
import json
import threading
from datetime import date, timedelta
from http.server import ThreadingHTTPServer
from urllib.error import HTTPError
from urllib.request import Request, urlopen

from cybersec.api import API_VERSION, make_handler
from cybersec.repository import Repository

TOKEN = "stage35-metrics-test-token-long-enough"


def _make_task(repo: Repository, *, title: str, severity: str, assignee: str, created: date, resolved: date | None):
    url = f"https://{title.lower().replace(' ', '-')}.example.com"
    repo.add_target(url, authorized=True)
    finding = repo.add_finding(url, title, severity, "Firm", title.lower().replace(" ", "-"))
    task = repo.upsert_remediation_task(finding.id, status="in_progress", assignee=assignee)
    with __import__("cybersec.db", fromlist=["connect"]).connect(repo.db_path) as db:
        db.execute("UPDATE remediation_tasks SET created_at=?, updated_at=? WHERE id=?",
                   (created.isoformat() + "T00:00:00Z", (resolved or created).isoformat() + "T00:00:00Z", task["id"]))
        db.execute("UPDATE remediation_history SET changed_at=? WHERE task_id=? AND event_type='created'",
                   (created.isoformat() + "T00:00:00Z", task["id"]))
    if resolved:
        repo.upsert_remediation_task(finding.id, status="resolved", assignee=assignee)
        with __import__("cybersec.db", fromlist=["connect"]).connect(repo.db_path) as db:
            db.execute("UPDATE remediation_tasks SET updated_at=? WHERE id=?", (resolved.isoformat() + "T00:00:00Z", task["id"]))
            db.execute("UPDATE remediation_history SET changed_at=? WHERE task_id=? AND new_status='resolved'",
                       (resolved.isoformat() + "T00:00:00Z", task["id"]))
        repo.record_remediation_verification(task["id"], outcome="verified", evidence="retest passed", verified_by="qa")
    return task


def test_metrics_calculate_resolution_sla_verification_and_groupings(tmp_path):
    repo = Repository(tmp_path / "metrics.db")
    today = date.today()
    first = _make_task(repo, title="Fast Critical", severity="Critical", assignee="alice", created=today - timedelta(days=5), resolved=today - timedelta(days=2))
    _make_task(repo, title="Slow High", severity="High", assignee="bob", created=today - timedelta(days=40), resolved=today - timedelta(days=20))
    _make_task(repo, title="Open Medium", severity="Medium", assignee="alice", created=today - timedelta(days=1), resolved=None)

    report = repo.remediation_metrics(start_date=(today - timedelta(days=45)).isoformat(), end_date=today.isoformat())
    assert report["summary"]["tasks_created"] == 3
    assert report["summary"]["resolved_in_period"] == 2
    assert report["summary"]["average_resolution_days"] == 11.5
    assert report["summary"]["median_resolution_days"] == 11.5
    assert report["summary"]["sla_compliance_percent"] == 50.0
    assert report["summary"]["verified_task_percent"] == 66.67
    assert {item["name"] for item in report["by_assignee"]} == {"alice", "bob"}
    assert len(report["by_severity"]) == 3
    assert len(report["by_target"]) == 3
    assert any(item["task_id"] == first["id"] and item["latest_verification"] == "verified" for item in report["tasks"])


def test_metrics_validate_date_range_and_empty_period(tmp_path):
    repo = Repository(tmp_path / "empty.db")
    today = date.today().isoformat()
    empty = repo.remediation_metrics(start_date=today, end_date=today)
    assert empty["summary"]["tasks_created"] == 0
    assert empty["summary"]["average_resolution_days"] is None
    for kwargs in ({"start_date": "not-a-date"}, {"start_date": "2026-10-20", "end_date": "2026-10-01"}):
        try:
            repo.remediation_metrics(**kwargs)
        except ValueError:
            pass
        else:
            raise AssertionError("invalid date range accepted")


def test_metrics_api_auth_json_csv_and_openapi(tmp_path):
    repo = Repository(tmp_path / "api.db")
    today = date.today()
    _make_task(repo, title="API Finding", severity="High", assignee="team", created=today, resolved=today)
    server = ThreadingHTTPServer(("127.0.0.1", 0), make_handler(repo, TOKEN))
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    base = f"http://127.0.0.1:{server.server_port}"

    def call(path: str, auth: bool = True):
        headers = {}
        if auth:
            headers["Authorization"] = f"Bearer {TOKEN}"
        request = Request(base + path, headers=headers)
        try:
            with urlopen(request, timeout=3) as response:
                return response.status, response.headers, response.read()
        except HTTPError as exc:
            return exc.code, exc.headers, exc.read()

    try:
        assert API_VERSION == "2.33.0"
        assert call("/api/v1/remediation/metrics", auth=False)[0] == 401
        status, headers, body = call("/api/v1/remediation/metrics")
        assert status == 200 and "application/json" in headers["Content-Type"]
        assert json.loads(body)["summary"]["tasks_created"] == 1
        status, headers, body = call("/api/v1/remediation/metrics.csv")
        assert status == 200 and "text/csv" in headers["Content-Type"]
        rows = list(csv.DictReader(io.StringIO(body.decode("utf-8-sig"))))
        assert len(rows) == 1 and rows[0]["severity"] == "High"
        assert call("/api/v1/remediation/metrics?start_date=bad-date")[0] == 400
        spec = json.loads(call("/openapi.json", auth=False)[2])
        assert "/api/v1/remediation/metrics" in spec["paths"]
        assert "/api/v1/remediation/metrics.csv" in spec["paths"]
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=2)


def test_dashboard_exposes_period_filters_and_exports():
    from cybersec.dashboard import dashboard_bytes
    html = dashboard_bytes().decode()
    assert "metrics-start" in html
    assert "metrics-end" in html
    assert "Remediation metrics JSON" in html
    assert "Remediation metrics CSV" in html
    assert "downloadRemediationMetrics" in html
