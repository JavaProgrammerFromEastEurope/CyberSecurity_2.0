from urllib.request import Request, urlopen

from test_stage22_api import api_server


def test_dashboard_is_available_without_auth_and_has_security_headers(api_server):
    request = Request(api_server + "/dashboard")
    with urlopen(request, timeout=2) as response:
        body = response.read().decode("utf-8")
        assert response.status == 200
        assert response.headers["Content-Type"].startswith("text/html")
        assert response.headers["Cache-Control"] == "no-store"
        assert "connect-src 'self'" in response.headers["Content-Security-Policy"]
        assert response.headers["X-Frame-Options"] == "DENY"
    assert "Cyber Security Orchestrator" in body
    assert "/api/v1/findings" in body
    assert "localStorage" not in body
    assert "sessionStorage" not in body


def test_health_version_is_updated(api_server):
    with urlopen(api_server + "/health", timeout=2) as response:
        import json
        payload = json.loads(response.read())
    assert payload["version"] == "2.33.0"
