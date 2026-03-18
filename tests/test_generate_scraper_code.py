import pytest
from types import SimpleNamespace

from mitmproxy_mcp.core import server


@pytest.mark.asyncio
async def test_generate_scraper_code_prefers_live_flow_body(monkeypatch):
    flow_id = "flow-live"

    def fake_get_flow_detail(fid):
        if fid != flow_id:
            return None
        return {
            "id": flow_id,
            "request": {
                "method": "POST",
                "url": "https://example.com/api/items",
                "headers": {"Content-Type": "application/json"},
                "body_preview": "db-preview-body",
            },
        }

    live_flow = SimpleNamespace(request=SimpleNamespace(content=b'{"source":"live"}'))

    monkeypatch.setattr(
        server.controller.recorder,
        "get_flow_detail",
        fake_get_flow_detail,
    )
    monkeypatch.setattr(
        server.controller.recorder,
        "get_live_flow",
        lambda fid: live_flow if fid == flow_id else None,
    )
    monkeypatch.setattr(
        server.controller.recorder.db,
        "get_flow_object",
        lambda fid: SimpleNamespace(body="db-body"),
    )

    code = await server.generate_scraper_code(flow_id)

    assert 'data_0 = "{\\"source\\":\\"live\\"}"' in code
    assert "db-body" not in code


@pytest.mark.asyncio
async def test_generate_scraper_code_uses_db_body(monkeypatch):
    flow_id = "flow-db"

    def fake_get_flow_detail(fid):
        if fid != flow_id:
            return None
        return {
            "id": flow_id,
            "request": {
                "method": "POST",
                "url": "https://example.com/api/items",
                "headers": {"Content-Type": "application/json"},
                "body_preview": "preview-body",
            },
        }

    monkeypatch.setattr(
        server.controller.recorder,
        "get_flow_detail",
        fake_get_flow_detail,
    )
    monkeypatch.setattr(
        server.controller.recorder,
        "get_live_flow",
        lambda fid: None,
    )
    monkeypatch.setattr(
        server.controller.recorder.db,
        "get_flow_object",
        lambda fid: SimpleNamespace(body="db-body"),
    )

    code = await server.generate_scraper_code(flow_id)

    assert 'data_0 = "db-body"' in code
