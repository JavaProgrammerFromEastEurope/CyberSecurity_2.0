import pytest

from cybersec.scope import ScopeError, normalize_target_url


def test_normalizes_url_and_drops_fragment():
    url, host = normalize_target_url("HTTPS://Example.COM:443/login#section")
    assert url == "https://example.com:443/login"
    assert host == "example.com"


@pytest.mark.parametrize("value", ["", "ftp://example.com", "https:///missing", "https://user:pass@example.com"])
def test_rejects_invalid_or_unsafe_url(value):
    with pytest.raises(ScopeError):
        normalize_target_url(value)
