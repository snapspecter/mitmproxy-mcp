import pytest
from mitmproxy.test.tflow import tflow

from mitmproxy_mcp.core.interceptor import TrafficInterceptor
from mitmproxy_mcp.core.scope import ScopeManager
from mitmproxy_mcp.core import server
from mitmproxy_mcp.models import InterceptionRule, ScopeConfig


def test_scope_matches_exact_domain_and_subdomains_only():
    scope = ScopeManager(ScopeConfig())
    scope.update_domains(["https://Example.COM/path"])

    assert scope.is_host_allowed("example.com")
    assert scope.is_host_allowed("api.example.com")
    assert not scope.is_host_allowed("example.com.attacker.test")
    assert not scope.is_host_allowed("notexample.com")


def test_empty_scope_denies_capture():
    scope = ScopeManager(ScopeConfig())
    flow = tflow()
    flow.request.host = "example.com"

    assert not scope.is_allowed(flow)


def test_interceptor_does_not_modify_out_of_scope_traffic():
    scope = ScopeManager(ScopeConfig())
    scope.update_domains(["example.com"])
    interceptor = TrafficInterceptor(scope)
    interceptor.add_rule(
        InterceptionRule(
            id="header",
            action_type="inject_header",
            key="X-Test",
            value="scoped",
        )
    )
    flow = tflow()
    flow.request.host = "unrelated.test"

    interceptor.request(flow)

    assert "X-Test" not in flow.request.headers


@pytest.mark.asyncio
async def test_start_proxy_requires_scope(monkeypatch):
    monkeypatch.setattr(server.controller.scope_config, "allowed_domains", [])

    result = await server.start_proxy()

    assert result.startswith("No active scope")


@pytest.mark.asyncio
async def test_clear_traffic_requires_confirmation(monkeypatch):
    cleared = False

    def mark_cleared():
        nonlocal cleared
        cleared = True

    monkeypatch.setattr(server.controller.recorder, "clear", mark_cleared)
    assert "Not cleared" in await server.clear_traffic()
    assert not cleared
    await server.clear_traffic(confirm=True)
    assert cleared
