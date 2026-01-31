import pytest
from mitmproxy.test.tflow import tflow

from mitmproxy_mcp.models import InterceptionRule
from mitmproxy_mcp.core.interceptor import TrafficInterceptor


def test_add_remove_rule():
    """Test adding and removing interception rules."""
    interceptor = TrafficInterceptor()
    rule = InterceptionRule(id="test", action_type="block")
    interceptor.add_rule(rule)
    assert "test" in interceptor.rules
    interceptor.remove_rule("test")
    assert "test" not in interceptor.rules


def test_header_injection():
    """Test injecting headers into requests."""
    interceptor = TrafficInterceptor()
    rule = InterceptionRule(
        id="h1",
        action_type="inject_header",
        key="X-Test",
        value="FoundIt",
        resource_type="request",
    )
    interceptor.add_rule(rule)

    f = tflow()
    interceptor.request(f)
    assert f.request.headers["X-Test"] == "FoundIt"


def test_block_request():
    """Test blocking requests."""
    interceptor = TrafficInterceptor()
    rule = InterceptionRule(id="b1", action_type="block", resource_type="request")
    interceptor.add_rule(rule)

    f = tflow()
    f.kill = lambda: setattr(f, "killed", True)  # Mock kill
    f.killed = False

    interceptor.request(f)
    assert f.killed
