import json
import threading
from http.server import ThreadingHTTPServer
from urllib.error import HTTPError
from urllib.request import Request, urlopen

import pytest

from cybersec.api import make_handler, serve_api
from cybersec.repository import Repository

TOKEN = "test-token-that-is-at-least-24-chars"


@pytest.fixture()
def api_server(tmp_path):
    repo = Repository(tmp_path / "api.db")
    server = ThreadingHTTPServer(("127.0.0.1", 0), make_handler(repo, TOKEN))
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    yield f"http://127.0.0.1:{server.server_port}"
    server.shutdown()
    server.server_close()
    thread.join(timeout=2)


def request(base, path, method="GET", body=None, token=TOKEN):
    data = None if body is None else json.dumps(body).encode()
    headers = {}
    if token is not None:
        headers["Authorization"] = f"Bearer {token}"
    if data is not None:
        headers["Content-Type"] = "application/json"
    req = Request(base + path, data=data, headers=headers, method=method)
    try:
        with urlopen(req, timeout=2) as response:
            return response.status, json.loads(response.read())
    except HTTPError as exc:
        return exc.code, json.loads(exc.read())


def test_health_is_local_and_returns_json(api_server):
    status, body = request(api_server, "/health", token=None)
    assert status == 200
    assert body["ok"] is True


def test_protected_endpoints_reject_missing_or_wrong_token(api_server):
    assert request(api_server, "/targets", token=None)[0] == 401
    assert request(api_server, "/targets", token="wrong-token-value-long-enough")[0] == 401


def test_target_requires_explicit_authorization_and_job_stays_queued(api_server):
    assert request(api_server, "/targets", "POST", {"url": "https://example.com"})[0] == 403
    status, target = request(api_server, "/targets", "POST", {
        "url": "https://example.com", "authorized": True
    })
    assert status == 201 and target["authorized"] is True
    status, job = request(api_server, "/jobs", "POST", {
        "target_url": "https://example.com", "tool": "demo"
    })
    assert status == 201
    assert job["status"] == "queued"
    assert request(api_server, "/jobs")[1]["items"][0]["status"] == "queued"


def test_api_rejects_unknown_routes_and_unsupported_mutations(api_server):
    assert request(api_server, "/not-real")[0] == 404
    assert request(api_server, "/targets", "DELETE")[0] == 405


def test_api_does_not_allow_unauthorized_target_job(api_server):
    status, _ = request(api_server, "/targets", "POST", {
        "url": "https://example.org", "authorized": True
    })
    assert status == 201
    status, _ = request(api_server, "/jobs", "POST", {
        "target_url": "https://not-registered.example", "tool": "demo"
    })
    assert status == 400


def test_server_refuses_non_loopback_and_weak_token(tmp_path):
    repo = Repository(tmp_path / "safe.db")
    with pytest.raises(ValueError, match="loopback"):
        serve_api(repo, host="0.0.0.0", port=8765, token=TOKEN)
    with pytest.raises(ValueError, match="24 characters"):
        serve_api(repo, host="127.0.0.1", port=8765, token="short")


def test_versioned_routes_support_pagination(api_server):
    for host in ("https://example.com", "https://example.org", "https://example.net"):
        status, _ = request(api_server, "/api/v1/targets", "POST", {"url": host, "authorized": True})
        assert status == 201
    status, page = request(api_server, "/api/v1/targets?limit=2&offset=1")
    assert status == 200
    assert page["total"] == 3
    assert page["limit"] == 2 and page["offset"] == 1
    assert len(page["items"]) == 2


def test_pagination_parameters_are_validated(api_server):
    assert request(api_server, "/api/v1/targets?limit=0")[0] == 400
    assert request(api_server, "/api/v1/targets?limit=501")[0] == 400
    assert request(api_server, "/api/v1/targets?offset=-1")[0] == 400
    assert request(api_server, "/api/v1/targets?limit=nope")[0] == 400


def test_job_filters_work_on_versioned_routes(api_server):
    request(api_server, "/api/v1/targets", "POST", {"url": "https://example.com", "authorized": True})
    request(api_server, "/api/v1/jobs", "POST", {"target_url": "https://example.com", "tool": "demo"})
    request(api_server, "/api/v1/jobs", "POST", {"target_url": "https://example.com", "tool": "zap"})
    status, response = request(api_server, "/api/v1/jobs?tool=zap&status=queued")
    assert status == 200
    assert response["total"] == 1
    assert response["items"][0]["tool"] == "zap"


def test_openapi_document_is_available_without_auth(api_server):
    status, spec = request(api_server, "/openapi.json", token=None)
    assert status == 200
    assert spec["openapi"] == "3.1.0"
    assert "/api/v1/findings" in spec["paths"]
    assert spec["components"]["securitySchemes"]["BearerAuth"]["scheme"] == "bearer"
