import json
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.error import HTTPError

import pytest

from cybersec.api import make_handler
from cybersec.api_client import (
    APIConnectionError,
    APIProtocolError,
    APIResponseError,
    CyberSecAPIClient,
)
from cybersec.repository import Repository

TOKEN = "stage25-test-token-with-more-than-24-characters"


@pytest.fixture()
def api_server(tmp_path):
    import cybersec.api as api_module
    with api_module._rate_lock:
        api_module._rate_events.clear()
    repo = Repository(tmp_path / "stage25.db")
    server = ThreadingHTTPServer(("127.0.0.1", 0), make_handler(repo, TOKEN))
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    yield f"http://127.0.0.1:{server.server_port}", repo
    server.shutdown()
    server.server_close()
    thread.join(timeout=2)
    with api_module._rate_lock:
        api_module._rate_events.clear()


def test_client_end_to_end_lists_and_details(api_server):
    base, _ = api_server
    client = CyberSecAPIClient(base, token=TOKEN, retry_backoff=0)
    target = client.create_target("https://example.com", authorized=True)
    job = client.create_job("https://example.com", tool="demo")
    assert target["id"] == client.get_target(target["id"])["id"]
    assert job["id"] == client.get_job(job["id"])["id"]
    page = client.list_targets(limit=10, offset=0)
    assert page.total == 1 and page.items[0]["url"] == "https://example.com/"
    assert client.list_jobs(tool="demo").total == 1
    assert client.health()["ok"] is True
    assert client.openapi()["openapi"] == "3.1.0"


def test_client_requires_loopback_and_token():
    with pytest.raises(ValueError, match="loopback"):
        CyberSecAPIClient("http://example.com:8765", token=TOKEN)
    with pytest.raises(ValueError, match="token"):
        CyberSecAPIClient(token=" ")
    with pytest.raises(ValueError, match="credentials"):
        CyberSecAPIClient("http://user:pass@127.0.0.1:8765", token=TOKEN)


def test_mutating_operations_require_explicit_authorization_and_validate_ids(api_server):
    base, _ = api_server
    client = CyberSecAPIClient(base, token=TOKEN, retry_backoff=0)
    with pytest.raises(ValueError, match="authorized=True"):
        client.create_target("https://example.com", authorized=False)
    with pytest.raises(ValueError, match="positive integer"):
        client.get_job(0)
    with pytest.raises(APIResponseError) as error:
        client.get_job(99999)
    assert error.value.status == 404
    assert error.value.code == "not_found"


def test_get_retries_retryable_http_errors_but_post_does_not_retry():
    state = {"get": 0, "post": 0}

    class Handler(BaseHTTPRequestHandler):
        def log_message(self, *_args):
            pass
        def do_GET(self):
            state["get"] += 1
            if state["get"] == 1:
                self.send_response(503)
                self.send_header("Content-Type", "application/json")
                self.end_headers()
                self.wfile.write(b'{"error":"busy","code":"busy"}')
                return
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            self.wfile.write(b'{"ok":true}')
        def do_POST(self):
            state["post"] += 1
            self.send_response(503)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            self.wfile.write(b'{"error":"busy","code":"busy"}')

    server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        client = CyberSecAPIClient(f"http://127.0.0.1:{server.server_port}", token=TOKEN, retries=2, retry_backoff=0)
        assert client.request("GET", "/api/v1/targets")["ok"] is True
        assert state["get"] == 2
        with pytest.raises(APIResponseError):
            client.request("POST", "/api/v1/targets", body={"authorized": True, "url": "https://example.com"})
        assert state["post"] == 1
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=2)


def test_invalid_response_json_raises_protocol_error(monkeypatch):
    class FakeResponse:
        def __enter__(self): return self
        def __exit__(self, *_args): return False
        def read(self, _limit): return b"not-json"
    monkeypatch.setattr("cybersec.api_client.urlopen", lambda *_args, **_kwargs: FakeResponse())
    client = CyberSecAPIClient(token=TOKEN, retries=0)
    with pytest.raises(APIProtocolError):
        client.health()


def test_unknown_routes_and_methods_are_rejected_before_network():
    client = CyberSecAPIClient(token=TOKEN)
    with pytest.raises(ValueError, match="known local API route"):
        client.request("GET", "/admin")
    with pytest.raises(ValueError, match="only GET and POST"):
        client.request("DELETE", "/api/v1/jobs/1")
