import pytest
from mitmproxy.test.tflow import tflow

from mitmproxy_mcp.core.scope import ScopeManager, host_in_scope
from mitmproxy_mcp.models import ScopeConfig


def _flow(host: str, path: str = "/", method: str = "GET"):
    f = tflow()
    f.request.host = host
    f.request.path = path
    f.request.method = method
    return f


@pytest.mark.parametrize(
    "host",
    [
        "evilexample.com",
        "notexample.com",
        "example.com.attacker.net",
        "evil-example.com.evil.io",
    ],
)
def test_scope_rejects_substring_and_suffix_attacks(host):
    assert host_in_scope(host, ["example.com"]) is False


@pytest.mark.parametrize("host", ["example.com", "api.example.com", "EXAMPLE.COM."])
def test_scope_allows_exact_and_subdomain(host):
    assert host_in_scope(host, ["example.com"]) is True


def test_scope_empty_allowlist_allows_all():
    scope = ScopeManager(ScopeConfig(allowed_domains=[]))
    assert scope.is_allowed(_flow("anything.test")) is True


def test_scope_manager_uses_exact_matching():
    scope = ScopeManager(ScopeConfig(allowed_domains=["example.com"]))
    assert scope.is_allowed(_flow("example.com.attacker.net")) is False
    assert scope.is_allowed(_flow("api.example.com")) is True


def test_scope_extension_and_method_filters():
    scope = ScopeManager(ScopeConfig(allowed_domains=[]))
    assert scope.is_allowed(_flow("example.com", path="/img/logo.png")) is False
    assert scope.is_allowed(_flow("example.com", method="OPTIONS")) is False
