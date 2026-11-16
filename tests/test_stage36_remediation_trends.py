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

TOKEN = "stage36-trends-test-token-long-enough"


def make_task(repo: Repository, title: str, created: date, resolved: date | None = None):
    url = f"https://{title.lower().replace(' ', '-')}.example.test"
    repo.add_target(url, authorized=True)
    finding = repo.add_finding(url, title, "High", "Firm", title.lower().replace(" ", "-"))
    task = repo.upsert_remediation_task(finding.id, status="in_progress", assignee="secops")
    with connect(repo.db_path) as db:
        db.execute("UPDATE remediation_tasks SET created_at=?,updated_at=? WHERE id=?",
                   (created.isoformat()+"T00:00:00Z", created.isoformat()+"T00:00:00Z", task["id"]))
        db.execute("UPDATE remediation_history SET changed_at=? WHERE task_id=? AND event_type='created'",
                   (created.isoformat()+"T00:00:00Z", task["id"]))
    if resolved:
        repo.record_remediation_verification(task["id"], outcome="verified", evidence="test evidence")
        repo.upsert_remediation_task(finding.id, status="resolved", assignee="secops")
        with connect(repo.db_path) as db:
            db.execute("UPDATE remediation_history SET changed_at=? WHERE task_id=? AND new_status='resolved'",
                       (resolved.isoformat()+"T00:00:00Z", task["id"]))
            db.execute("UPDATE remediation_tasks SET updated_at=? WHERE id=?",
                       (resolved.isoformat()+"T00:00:00Z", task["id"]))
    return task


def test_daily_trends_and_previous_equal_length_period(tmp_path):
    repo = Repository(tmp_path / "trends.db")
    today = date.today()
    start = today - timedelta(days=6)
    make_task(repo, "Current Open", today - timedelta(days=1))
    make_task(repo, "Current Resolved", today - timedelta(days=3), today - timedelta(days=2))
    make_task(repo, "Previous Task", start - timedelta(days=1))
    report = repo.remediation_trends(start_date=start.isoformat(), end_date=today.isoformat())
    assert report["period"]["days"] == 7
    assert report["previous_period"]["start_date"] == (start - timedelta(days=7)).isoformat()
    assert len(report["daily"]) == 7
    assert sum(x["created"] for x in report["daily"]) == 2
    assert sum(x["resolved"] for x in report["daily"]) == 1
    assert report["comparison"]["tasks_created"]["current"] == 2
    assert report["comparison"]["tasks_created"]["previous"] == 1


def test_snapshots_are_persistent_and_validated(tmp_path):
    path = tmp_path / "snapshots.db"
    repo = Repository(path)
    today = date.today().isoformat()
    saved = repo.save_remediation_trend_snapshot(start_date=today, end_date=today)
    assert saved["id"] == 1
    assert repo.list_remediation_trend_snapshots()[0]["id"] == 1
    assert repo.get_remediation_trend_snapshot(1)["report"]["period"]["days"] == 1
    repo2 = Repository(path)
    assert repo2.get_remediation_trend_snapshot(1)["id"] == 1
    try:
        repo.get_remediation_trend_snapshot(999)
    except ValueError:
        pass
    else:
        raise AssertionError("missing snapshot should be rejected")
    try:
        repo.list_remediation_trend_snapshots(0)
    except ValueError:
        pass
    else:
        raise AssertionError("invalid limit should be rejected")


def test_trends_snapshot_api_auth_and_openapi(tmp_path):
    repo = Repository(tmp_path / "api.db")
    today = date.today().isoformat()
    server = ThreadingHTTPServer(("127.0.0.1", 0), make_handler(repo, TOKEN))
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    base = f"http://127.0.0.1:{server.server_port}"

    def call(path, method="GET", body=None, auth=True):
        headers = {}
        if auth:
            headers["Authorization"] = f"Bearer {TOKEN}"
        payload = None
        if body is not None:
            payload = json.dumps(body).encode()
            headers["Content-Type"] = "application/json"
        req = Request(base + path, data=payload, headers=headers, method=method)
        try:
            with urlopen(req, timeout=3) as response:
                return response.status, response.headers, response.read()
        except HTTPError as exc:
            return exc.code, exc.headers, exc.read()

    try:
        assert API_VERSION == "2.33.0"
        assert call("/api/v1/remediation/trends", auth=False)[0] == 401
        status, _, body = call(f"/api/v1/remediation/trends?start_date={today}&end_date={today}")
        assert status == 200 and json.loads(body)["period"]["days"] == 1
        status, _, body = call("/api/v1/remediation/trend-snapshots", method="POST", body={"start_date": today, "end_date": today})
        assert status == 201
        snapshot = json.loads(body)
        assert snapshot["id"] == 1
        assert call("/api/v1/remediation/trend-snapshots")[0] == 200
        assert call("/api/v1/remediation/trend-snapshots/1")[0] == 200
        assert call("/api/v1/remediation/trends?start_date=bad-date")[0] == 400
        spec = json.loads(call("/openapi.json")[2])
        assert "/api/v1/remediation/trends" in spec["paths"]
        assert "/api/v1/remediation/trend-snapshots" in spec["paths"]
    finally:
        server.shutdown()
        thread.join(timeout=3)
        server.server_close()
