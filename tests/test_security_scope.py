from types import SimpleNamespace

from mitmproxy_mcp.core.scope import ScopeManager
from mitmproxy_mcp.models import ScopeConfig


def test_scope_manager_domain_matching():
    config = ScopeConfig(allowed_domains=["example.com"])
    manager = ScopeManager(config)

    flow_sub = SimpleNamespace(
        request=SimpleNamespace(host="sub.example.com", path="/api", method="GET")
    )
    assert manager.is_allowed(flow_sub) is True

    flow_exact = SimpleNamespace(
        request=SimpleNamespace(host="example.com", path="/api", method="GET")
    )
    assert manager.is_allowed(flow_exact) is True

    flow_evil1 = SimpleNamespace(
        request=SimpleNamespace(host="notexample.com", path="/api", method="GET")
    )
    assert manager.is_allowed(flow_evil1) is False

    flow_evil2 = SimpleNamespace(
        request=SimpleNamespace(host="example.com.evil.org", path="/api", method="GET")
    )
    assert manager.is_allowed(flow_evil2) is False
