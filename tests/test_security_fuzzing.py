from types import SimpleNamespace
import pytest

from mitmproxy_mcp.core import server


@pytest.mark.asyncio
async def test_fuzz_endpoint_baseline_response(monkeypatch):
    flow_id = "flow-fuzz"
    flow_data = {
        "id": flow_id,
        "request": {
            "method": "GET",
            "url": "https://example.com/test?id=1",
            "headers": {},
        },
        "response": {
            "status_code": 200,
            "body_preview": "ok",
        },
    }

    monkeypatch.setattr(server.controller.recorder, "get_flow_detail", lambda fid: flow_data)

    class DummyClient:
        async def __aenter__(self):
            return self

        async def __aexit__(self, *args):
            pass

        async def request(self, **kwargs):
            return SimpleNamespace(status_code=200, content=b"ok")

    monkeypatch.setattr(server, "AsyncSession", lambda **kwargs: DummyClient())

    result = await server.fuzz_endpoint(
        flow_id=flow_id,
        target_param="id",
        param_type="query",
        payload_category="sqli",
    )
    assert "No significant anomalies detected" in result
