from test_stage22_api import api_server, request
from test_stage13_history import setup_pair


def test_saved_comparisons_list_and_detail_api(tmp_path):
    import json
    import threading
    from http.server import ThreadingHTTPServer
    from urllib.error import HTTPError
    from urllib.request import Request, urlopen
    from cybersec.api import make_handler
    from cybersec.comparison import compare_jobs
    from cybersec.repository import Repository

    token = "comparison-api-test-token-long-enough"
    repo = Repository(tmp_path / "comparison-api.db")
    repo.add_target("https://example.com", authorized=True)
    before = repo.create_job("https://example.com", "demo")
    after = repo.create_job("https://example.com", "demo")
    repo.save_comparison(compare_jobs(repo, before.id, after.id))
    server = ThreadingHTTPServer(("127.0.0.1", 0), make_handler(repo, token))
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    base = f"http://127.0.0.1:{server.server_port}"
    def get(path):
        req = Request(base + path, headers={"Authorization": f"Bearer {token}"})
        try:
            with urlopen(req, timeout=2) as response:
                return response.status, json.loads(response.read())
        except HTTPError as exc:
            return exc.code, json.loads(exc.read())
    try:
        status, page = get("/api/v1/comparisons?limit=10")
        assert status == 200
        assert page["total"] == 1 and page["items"][0]["before_job_id"] == before.id
        status, detail = get(f"/api/v1/comparisons/{page['items'][0]['id']}")
        assert status == 200 and detail["result"]["summary"]["before_findings"] == 0
        assert get("/api/v1/comparisons/999")[0] == 404
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=2)


def test_dashboard_exposes_comparison_trends_and_csv_features(api_server):
    from urllib.request import Request, urlopen
    with urlopen(Request(api_server + "/dashboard"), timeout=2) as response:
        html = response.read().decode("utf-8")
    assert 'data-tab="comparisons"' in html
    assert "/api/v1/comparisons?limit=500" in html
    assert "Finding severity distribution" in html
    assert "Export CSV" in html
    assert "function exportCSV()" in html
