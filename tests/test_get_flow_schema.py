import pytest
import json
from types import SimpleNamespace

from mitmproxy_mcp.core import server


@pytest.mark.asyncio
async def test_get_flow_schema_json_object(monkeypatch):
    flow_id = "test-flow"

    def fake_get_flow_detail(fid):
        if fid != flow_id:
            return None
        return {
            "response": {
                "status_code": 200,
                "headers": {"Content-Type": "application/json"},
                "body_preview": '{"id": 123, "name": "test", "active": true, "tags": ["a", "b"]}',
            }
        }

    monkeypatch.setattr(
        server.controller.recorder,
        "get_flow_detail",
        fake_get_flow_detail,
    )

    result = await server.get_flow_schema(flow_id)
    schema = json.loads(result)

    expected = {
        "id": "int",
        "name": "str",
        "active": "bool",
        "tags": "list",
    }
    assert schema == expected


@pytest.mark.asyncio
async def test_get_flow_schema_full_body_from_db(monkeypatch):
    flow_id = "test-flow-db"

    def fake_get_flow_detail(fid):
        if fid != flow_id:
            return None
        return {
            "response": {
                "status_code": 200,
                "headers": {"Content-Type": "application/json"},
                "body_preview": "preview",
            }
        }

    fake_flow_obj = SimpleNamespace(response=SimpleNamespace(content=b'{"user_id": 456, "email": "user@example.com"}'))

    def fake_get_flow_object(fid):
        if fid == flow_id:
            return fake_flow_obj
        return None

    monkeypatch.setattr(
        server.controller.recorder,
        "get_flow_detail",
        fake_get_flow_detail,
    )
    monkeypatch.setattr(
        server.controller.recorder.db,
        "get_flow_object",
        fake_get_flow_object,
    )

    result = await server.get_flow_schema(flow_id)
    schema = json.loads(result)

    expected = {
        "user_id": "int",
        "email": "str",
    }
    assert schema == expected


@pytest.mark.asyncio
async def test_get_flow_schema_not_json(monkeypatch):
    flow_id = "test-flow-html"

    def fake_get_flow_detail(fid):
        if fid != flow_id:
            return None
        return {
            "response": {
                "status_code": 200,
                "headers": {"Content-Type": "text/html"},
                "body_preview": "<html><body>Hello</body></html>",
            }
        }

    monkeypatch.setattr(
        server.controller.recorder,
        "get_flow_detail",
        fake_get_flow_detail,
    )

    result = await server.get_flow_schema(flow_id)
    assert result == "Response body is not valid JSON."


@pytest.mark.asyncio
async def test_get_flow_schema_json_array(monkeypatch):
    flow_id = "test-flow-array"

    def fake_get_flow_detail(fid):
        if fid != flow_id:
            return None
        return {
            "response": {
                "status_code": 200,
                "headers": {"Content-Type": "application/json"},
                "body_preview": '[{"id": 1}, {"id": 2}]',
            }
        }

    monkeypatch.setattr(
        server.controller.recorder,
        "get_flow_detail",
        fake_get_flow_detail,
    )

    result = await server.get_flow_schema(flow_id)
    assert result == "Response is JSON but not an object (it's list)."


@pytest.mark.asyncio
async def test_get_flow_schema_flow_not_found(monkeypatch):
    def fake_get_flow_detail(fid):
        return None

    monkeypatch.setattr(
        server.controller.recorder,
        "get_flow_detail",
        fake_get_flow_detail,
    )

    result = await server.get_flow_schema("nonexistent")
    assert result == "Flow not found."
