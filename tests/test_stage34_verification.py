from __future__ import annotations

import json
import threading
from http.server import ThreadingHTTPServer
from urllib.error import HTTPError
from urllib.request import Request, urlopen

from cybersec.api import API_VERSION, make_handler
from cybersec.dashboard import dashboard_bytes
from cybersec.repository import Repository

TOKEN = "stage34-verification-test-token-long-enough"


def _finding(repo):
    repo.add_target("https://example.com", authorized=True)
    return repo.add_finding("https://example.com", "Example High", "High", "Firm", "xss")


def test_verification_history_and_summary(tmp_path):
    repo = Repository(tmp_path / "verify.db")
    finding = _finding(repo)
    task = repo.upsert_remediation_task(finding.id, status="in_progress")
    assert repo.latest_remediation_verification(task["id"]) is None
    first = repo.record_remediation_verification(task["id"], outcome="rejected", evidence="test failed", verified_by="qa")
    second = repo.record_remediation_verification(task["id"], outcome="verified", evidence="retest passed", notes="confirmed", verified_by="security")
    assert first["outcome"] == "rejected"
    assert second["outcome"] == "verified"
    assert repo.latest_remediation_verification(task["id"])["id"] == second["id"]
    assert len(repo.remediation_verification_history(task["id"])) == 2
    assert repo.remediation_verification_summary() == {"tasks": 1, "verified": 1, "rejected_or_failed": 0, "unverified": 0}
    assert repo.list_remediation_tasks()[0]["verification_status"] == "verified"
    for outcome in ("nope", ""):
        try:
            repo.record_remediation_verification(task["id"], outcome=outcome)
        except ValueError:
            pass
        else:
            raise AssertionError("invalid verification outcome accepted")


def test_api_requires_verification_before_resolved_and_authenticates_routes(tmp_path):
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
            with urlopen(request, timeout=3) as response:
                return response.status, json.loads(response.read())
        except HTTPError as exc:
            return exc.code, json.loads(exc.read())

    try:
        assert API_VERSION == "2.33.0"
        assert call("/api/v1/remediation/verification-summary", auth=False)[0] == 401
        assert call(f"/api/v1/findings/{finding.id}/remediation", "POST", {"status": "resolved"})[0] == 400
        _, task = call(f"/api/v1/findings/{finding.id}/remediation", "POST", {"status": "in_progress"})
        status, result = call(f"/api/v1/remediation/{task['id']}/verification", "POST", {"outcome": "verified", "evidence": "retest passed", "verified_by": "qa"})
        assert status == 200 and result["outcome"] == "verified"
        status, resolved = call(f"/api/v1/findings/{finding.id}/remediation", "POST", {"status": "resolved"})
        assert status == 200 and resolved["status"] == "resolved"
        assert call(f"/api/v1/remediation/{task['id']}/verification")[1]["total"] == 1
        assert call("/api/v1/remediation/verification-summary")[1]["verified"] == 1
        spec = call("/openapi.json", auth=False)[1]
        assert "/api/v1/remediation/{task_id}/verification" in spec["paths"]
    finally:
        server.shutdown(); server.server_close(); thread.join(timeout=2)

    html = dashboard_bytes().decode()
    assert "Verification evidence" in html
    assert "save-verification" in html
    assert "verification_status" in html
