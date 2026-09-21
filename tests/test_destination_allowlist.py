import pytest

from mitmproxy_mcp.core.netpolicy import check_destination, host_matches_scope


def test_scope_allows_exact_and_subdomain():
    assert host_matches_scope("example.com", ["example.com"]) is True
    assert host_matches_scope("api.example.com", ["example.com"]) is True
    assert host_matches_scope("example.com.attacker.net", ["example.com"]) is False


def test_off_scope_destination_denied():
    denial = check_destination("https://evil.test/x", ["example.com"])
    assert denial is not None
    assert "outside the configured scope" in denial


def test_on_scope_destination_allowed():
    assert check_destination("https://api.example.com/x", ["example.com"]) is None


def test_non_http_scheme_denied():
    assert check_destination("file:///etc/passwd", ["example.com"]) is not None
    assert check_destination("gopher://example.com/", ["example.com"]) is not None


def test_userinfo_denied():
    assert check_destination("https://user:pass@api.example.com/", ["example.com"]) is not None


@pytest.mark.parametrize(
    "url",
    [
        "http://127.0.0.1/",
        "http://localhost/",
        "http://169.254.169.254/latest/meta-data/",
        "http://10.0.0.5/",
        "http://192.168.1.1/",
        "http://[::1]/",
    ],
)
def test_private_and_metadata_addresses_denied_without_scope(url):
    assert check_destination(url, []) is not None
