import json
from pathlib import Path

import pytest

from mitmproxy_mcp.core.server import _safe_data_path, load_traffic_file


@pytest.mark.asyncio
async def test_path_traversal_denied(tmp_path, monkeypatch):
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    outside = tmp_path / "outside.har"
    outside.write_text('{"log": {"entries": []}}', encoding="utf-8")
    monkeypatch.setenv("MITMPROXY_MCP_DATA_DIR", str(workspace))

    result = json.loads(await load_traffic_file(str(outside)))

    assert result["status"] == "error"
    assert "Security Error" in result["message"]


@pytest.mark.asyncio
async def test_prefix_collision_path_denied(tmp_path, monkeypatch):
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    sibling = tmp_path / "workspace-escape"
    sibling.mkdir()
    outside = sibling / "traffic.har"
    outside.write_text('{"log": {"entries": []}}', encoding="utf-8")
    monkeypatch.setenv("MITMPROXY_MCP_DATA_DIR", str(workspace))

    result = json.loads(await load_traffic_file(str(outside)))

    assert result["status"] == "error"


@pytest.mark.asyncio
async def test_valid_workspace_path_allowed(tmp_path, monkeypatch):
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    local_file = workspace / "safe.har"
    local_file.write_text('{"log": {"entries": []}}', encoding="utf-8")
    monkeypatch.setenv("MITMPROXY_MCP_DATA_DIR", str(workspace))

    result = json.loads(await load_traffic_file("safe.har"))

    assert result["status"] == "ok"


def test_dump_path_is_confined(tmp_path, monkeypatch):
    workspace = tmp_path / "workspace"
    monkeypatch.setenv("MITMPROXY_MCP_DATA_DIR", str(workspace))

    assert Path(_safe_data_path("capture.flow")).parent == workspace.resolve()
    with pytest.raises(ValueError):
        _safe_data_path("../capture.flow")
