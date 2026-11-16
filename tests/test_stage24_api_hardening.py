import json
import threading
from http.server import ThreadingHTTPServer
from urllib.error import HTTPError
from urllib.request import Request, urlopen

import pytest

import cybersec.api as api_module
from cybersec.api import make_handler
from cybersec.repository import Repository

TOKEN = "stage24-test-token-with-more-than-24-chars"

@pytest.fixture()
def server(tmp_path):
    with api_module._rate_lock:
        api_module._rate_events.clear()
    repo = Repository(tmp_path / "stage24.db")
    server = ThreadingHTTPServer(("127.0.0.1", 0), make_handler(repo, TOKEN))
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    yield f"http://127.0.0.1:{server.server_port}", repo
    server.shutdown(); server.server_close(); thread.join(timeout=2)
    with api_module._rate_lock:
        api_module._rate_events.clear()


def call(base, path, method="GET", body=None):
    data = None if body is None else json.dumps(body).encode()
    headers = {"Authorization": f"Bearer {TOKEN}"}
    if data is not None:
        headers["Content-Type"] = "application/json"
    request = Request(base + path, data=data, headers=headers, method=method)
    try:
        with urlopen(request, timeout=2) as response:
            return response.status, json.loads(response.read()), response.headers
    except HTTPError as exc:
        return exc.code, json.loads(exc.read()), exc.headers


def test_detail_endpoints_return_one_resource_and_request_id(server):
    base, repo = server
    _, target, _ = call(base, "/api/v1/targets", "POST", {"url": "https://example.com", "authorized": True})
    _, job, _ = call(base, "/api/v1/jobs", "POST", {"target_url": "https://example.com", "tool": "demo"})
    status, got_target, headers = call(base, f"/api/v1/targets/{target['id']}")
    assert status == 200 and got_target["id"] == target["id"]
    assert headers["X-Request-ID"] == got_target["request_id"]
    assert call(base, f"/api/v1/jobs/{job['id']}")[1]["id"] == job["id"]
    assert call(base, "/api/v1/targets/999999")[0] == 404


def test_finding_detail_endpoint(server):
    base, repo = server
    repo.add_target("https://example.com", authorized=True)
    finding = repo.add_finding("https://example.com", "Example issue", "High", "Firm", "xss")
    status, payload, _ = call(base, f"/api/v1/findings/{finding.id}")
    assert status == 200 and payload["title"] == "Example issue"


def test_json_content_type_required_and_error_contract(server):
    base, _ = server
    request = Request(base + "/api/v1/targets", data=b'{"url":"https://example.com","authorized":true}',
                      headers={"Authorization": f"Bearer {TOKEN}"}, method="POST")
    with pytest.raises(HTTPError) as error:
        urlopen(request, timeout=2)
    assert error.value.code == 400
    payload = json.loads(error.value.read())
    assert payload["code"] == "invalid_request"
    assert payload["request_id"]
    assert error.value.headers["X-Request-ID"] == payload["request_id"]


def test_rate_limit_returns_429(server, monkeypatch):
    base, _ = server
    with api_module._rate_lock:
        api_module._rate_events.clear()
    monkeypatch.setattr(api_module, "RATE_LIMIT_MAX_REQUESTS", 1)
    assert call(base, "/health")[0] == 200
    status, payload, _ = call(base, "/health")
    assert status == 429
    assert payload["code"] == "rate_limit_exceeded"


def test_openapi_document_remains_spec_shaped(server):
    base, _ = server
    status, document, headers = call(base, "/openapi.json")
    assert status == 200
    assert document["openapi"] == "3.1.0"
    assert "request_id" not in document
    assert headers.get("X-Request-ID")
    assert "/api/v1/jobs/{job_id}" in document["paths"]
