import pytest
from cybersec.scanners import ScanContext, ZapPassiveAdapter


def test_zap_api_must_be_loopback():
    with pytest.raises(ValueError, match="non-loopback"):
        ZapPassiveAdapter(api_url="http://192.0.2.10:8080")


def test_zap_api_must_be_http_localhost():
    with pytest.raises(ValueError, match="loopback"):
        ZapPassiveAdapter(api_url="https://127.0.0.1:8080")


def test_target_origin_validation():
    adapter = ZapPassiveAdapter(api_url="http://127.0.0.1:8080")
    assert adapter._origin("https://example.com/path") == ("https", "example.com", 443)
    with pytest.raises(ValueError):
        adapter._origin("file:///etc/passwd")
    with pytest.raises(ValueError):
        adapter._origin("https://user:password@example.com")


def test_default_registry_contains_demo_and_zap():
    from cybersec.scanners import default_registry
    assert default_registry().names() == ("demo", "nuclei", "zap")
