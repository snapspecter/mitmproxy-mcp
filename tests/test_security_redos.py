import pytest
from mitmproxy.test.tflow import tflow

from mitmproxy_mcp.core.interceptor import TrafficInterceptor
from mitmproxy_mcp.core.server import add_interception_rule, controller, extract_session_variable
from mitmproxy_mcp.models import InterceptionRule


def test_interceptor_uses_safe_regex_for_url_patterns():
    interceptor = TrafficInterceptor()
    rule = InterceptionRule(
        id="redos_test",
        action_type="block",
        url_pattern=r"^(([a-z])+.)+[A-Z]([a-z])+$",
    )

    assert interceptor.add_rule(rule)

    flow = tflow()
    flow.request.url = "http://example.com/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa!"
    flow.kill = lambda: setattr(flow, "killed", True)
    flow.killed = False

    interceptor.request(flow)

    assert not flow.killed


def test_unsupported_regex_does_not_add_rule():
    interceptor = TrafficInterceptor()
    rule = InterceptionRule(
        id="lookahead_test",
        action_type="block",
        url_pattern=r"foo(?=bar)",
    )

    assert not interceptor.add_rule(rule)

    assert "lookahead_test" not in interceptor.rules
    assert "lookahead_test" not in interceptor._compiled_patterns


@pytest.mark.asyncio
async def test_add_interception_rule_reports_unsupported_regex():
    result = await add_interception_rule(
        rule_id="lookahead_api_test",
        action_type="block",
        url_pattern=r"foo(?=bar)",
    )

    assert result == "Invalid or unsupported regex for rule 'lookahead_api_test'"


@pytest.mark.asyncio
async def test_extract_session_variable_rejects_unsupported_regex(monkeypatch):
    class Recorder:
        def get_flow_detail(self, flow_id):
            return {"response": {"body_preview": "foobar"}}

    monkeypatch.setattr(controller, "recorder", Recorder())

    result = await extract_session_variable("token", "flow-id", r"foo(?=bar)")

    assert result.startswith("Error applying regex:")
