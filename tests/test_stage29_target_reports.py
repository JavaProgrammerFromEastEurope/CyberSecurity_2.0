import json
import threading
from http.server import ThreadingHTTPServer
from urllib.error import HTTPError
from urllib.request import Request, urlopen

from cybersec.api import make_handler
from cybersec.repository import Repository
from test_stage22_api import api_server

TOKEN = "stage29-target-report-token-long-enough"


def test_target_report_contains_related_metadata_and_daily_trend(tmp_path):
    repo = Repository(tmp_path / "target-report.db")
    target = repo.add_target("https://example.com", authorized=True)
    job = repo.create_job("https://example.com", "demo")
    repo.add_finding("https://example.com", "Example issue", "High", "Firm", "xss", url="https://example.com/path")
    server = ThreadingHTTPServer(("127.0.0.1", 0), make_handler(repo, TOKEN))
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    base = f"http://127.0.0.1:{server.server_port}"

    def get(path, auth=True):
        headers = {"Authorization": f"Bearer {TOKEN}"} if auth else {}
        request = Request(base + path, headers=headers)
        try:
            with urlopen(request, timeout=2) as response:
                return response.status, json.loads(response.read())
        except HTTPError as exc:
            return exc.code, json.loads(exc.read())

    try:
        status, report = get(f"/api/v1/targets/{target.id}/report")
        assert status == 200
        assert report["target"]["id"] == target.id
        assert report["summary"]["job_count"] == 1
        assert report["jobs"][0]["id"] == job.id
        assert report["summary"]["finding_count"] == 1
        assert report["summary"]["severity"]["High"] == 1
        assert report["daily_trend"][0]["total"] == 1
        assert get("/api/v1/targets/999/report")[0] == 404
        assert get(f"/api/v1/targets/{target.id}/report", auth=False)[0] == 401
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=2)


def test_dashboard_exposes_target_report_and_json_export(api_server):
    with urlopen(Request(api_server + "/dashboard"), timeout=2) as response:
        html = response.read().decode("utf-8")
    assert "/api/v1/targets/" in html and "+'/report'" in html
    assert "Load target report" in html
    assert "Export target report JSON" in html
    assert "function downloadTargetReport()" in html
    assert "Compare 2 selected jobs" in html
    assert "function compareSelectedJobs()" in html
