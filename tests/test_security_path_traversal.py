import pytest
import os
import json
import asyncio
from pathlib import Path
from mitmproxy_mcp.core.server import load_traffic_file

@pytest.mark.asyncio
async def test_relative_path_traversal_denied():
    """Relative '..' traversal is still blocked."""
    result_str = await load_traffic_file("../../../../../tmp/mitm_traversal_test.har")
    result = json.loads(result_str)

    assert result["status"] == "error"
    assert "Security Error" in result["message"]
    assert "Path traversal" in result["message"]


@pytest.mark.asyncio
async def test_absolute_path_allowed(tmp_path):
    """Absolute paths outside CWD are accepted (common when loading exported flows)."""
    target = tmp_path / "capture.har"
    target.write_text('{"log": {"entries": []}}')

    result_str = await load_traffic_file(str(target))
    result = json.loads(result_str)

    # Should import successfully (0 entries is fine — empty HAR)
    assert result["status"] == "ok"


@pytest.mark.asyncio
async def test_valid_relative_path_allowed():
    """A plain relative path (no '..') within the project still works."""
    local_file = Path("test_safe_import.har")
    local_file.write_text('{"log": {"entries": []}}')

    try:
        result_str = await load_traffic_file("test_safe_import.har")
        result = json.loads(result_str)

        assert result["status"] == "ok"
    finally:
        if local_file.exists():
            local_file.unlink()
