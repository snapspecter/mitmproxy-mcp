import json

import pytest
from pydantic import ValidationError
from mitmproxy.test.tflow import tflow

from mitmproxy_mcp.core import server
from mitmproxy_mcp.core.interceptor import TrafficInterceptor
from mitmproxy_mcp.models import InterceptionRule
from mitmproxy_mcp.core.sanitize import (
    strip_crlf,
    validate_header,
    is_safe_header_name,
)


@pytest.mark.parametrize("payload", ["\r", "\n", "\r\n", "\x00"])
def test_validate_header_rejects_control_characters(payload):
    error = validate_header("X-Test", f"ok{payload}X-Evil: 1")
    assert error is not None


@pytest.mark.parametrize("name", ["X-Test\r\nX-Evil", "Bad Name", "", "X-Test:evil"])
def test_header_name_must_be_a_token(name):
    assert is_safe_header_name(name) is False


def test_strip_crlf_removes_all_control_characters():
    assert strip_crlf("a\r\nb\x00c") == "abc"


def test_inject_header_crlf_is_rejected_by_the_model():
    with pytest.raises(ValidationError):
        InterceptionRule(
            id="crlf",
            action_type="inject_header",
            key="X-Test",
            value="ok\r\nX-Evil: 1",
        )


def test_inject_header_crlf_is_rejected_by_the_interceptor():
    interceptor = TrafficInterceptor()
    # Bypass the pydantic model to prove the interceptor is its own gate.
    rule = InterceptionRule.model_construct(
        id="crlf-bypass", action_type="inject_header", key="X-Test", value="ok\r\nX-Evil: 1"
    )
    assert interceptor.add_rule(rule) is False
    assert "crlf-bypass" not in interceptor.rules


def test_interceptor_does_not_emit_injected_header():
    interceptor = TrafficInterceptor()
    rule = InterceptionRule(
        id="ok",
        action_type="inject_header",
        key="X-Test",
        value="found-it",
    )
    assert interceptor.add_rule(rule) is True
    flow = tflow()
    interceptor.request(flow)
    assert flow.request.headers["X-Test"] == "found-it"
    assert "X-Evil" not in flow.request.headers


@pytest.mark.asyncio
async def test_set_global_header_rejects_crlf():
    result = await server.set_global_header("X-A", "v\r\nInjected: 1")
    assert "Refusing" in result
    assert "global_x-a" not in server.controller.interceptor.rules


@pytest.mark.asyncio
async def test_add_interception_rule_rejects_crlf():
    result = await server.add_interception_rule(
        rule_id="crlf-api",
        action_type="inject_header",
        key="X-A",
        value="v\r\nInjected: 1",
    )
    assert "Invalid rule parameters" in result
    assert "crlf-api" not in server.controller.interceptor.rules


@pytest.mark.asyncio
async def test_extract_session_variable_rejects_crlf_value(monkeypatch):
    class Recorder:
        def get_flow_detail(self, flow_id):
            return {"response": {"body_preview": "token=abc\r\nX-Evil: 1"}}

    monkeypatch.setattr(server.controller, "recorder", Recorder())

    result = await server.extract_session_variable("tok", "f", r"token=(.+)")
    assert "rejected" in result
    assert "tok" not in server.controller.session_variables


def test_generated_curl_redacts_credentials():
    from mitmproxy_mcp.core.recorder import SimpleRequest, TrafficDB

    db = TrafficDB(db_path=":memory:")
    curl = db._generate_curl(
        SimpleRequest(
            method="GET",
            url="https://example.com/",
            headers={"Authorization": "Bearer supersecret", "Cookie": "session=abc"},
            body=None,
        )
    )
    assert "supersecret" not in curl
    assert "session=abc" not in curl
    assert "<REDACTED>" in curl
