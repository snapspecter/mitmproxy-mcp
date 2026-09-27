import json
import os
from pathlib import Path
from unittest.mock import patch

import pytest

from mitmproxy_mcp.core import server


@pytest.mark.asyncio
async def test_dump_file_denies_outside_path(tmp_path, monkeypatch):
    monkeypatch.setattr(Path, "cwd", classmethod(lambda cls: tmp_path))
    outside_file = tmp_path.parent / "outside.flow"

    result_str = await server.start_proxy(dump_file=str(outside_file))
    result = json.loads(result_str)

    assert result["status"] == "error"
    assert "Security Error" in result["message"]
    assert "Access denied" in result["message"]
    assert not outside_file.exists()


@pytest.mark.asyncio
async def test_dump_file_denies_parent_traversal(tmp_path, monkeypatch):
    monkeypatch.setattr(Path, "cwd", classmethod(lambda cls: tmp_path))

    result_str = await server.start_proxy(dump_file="../traversal.flow")
    result = json.loads(result_str)

    assert result["status"] == "error"
    assert "Security Error" in result["message"]
    assert "Access denied" in result["message"]


@pytest.mark.asyncio
async def test_dump_file_denies_append_outside_path(tmp_path, monkeypatch):
    monkeypatch.setattr(Path, "cwd", classmethod(lambda cls: tmp_path))
    outside_file = tmp_path.parent / "append_outside.flow"

    result_str = await server.start_proxy(dump_file=f"+{outside_file}")
    result = json.loads(result_str)

    assert result["status"] == "error"
    assert "Security Error" in result["message"]
    assert "Access denied" in result["message"]
    assert not outside_file.exists()


@pytest.mark.asyncio
async def test_dump_file_denies_sibling_prefix(tmp_path, monkeypatch):
    base = tmp_path / "project"
    base.mkdir()
    sibling = tmp_path / "project-evil" / "out.flow"
    monkeypatch.setattr(Path, "cwd", classmethod(lambda cls: base))

    result_str = await server.start_proxy(dump_file=str(sibling))
    result = json.loads(result_str)

    assert result["status"] == "error"
    assert "Security Error" in result["message"]
    assert "Access denied" in result["message"]


@pytest.mark.asyncio
async def test_dump_file_denies_symlink_escape(tmp_path, monkeypatch):
    base = tmp_path / "project"
    base.mkdir()
    outside = tmp_path / "outside"
    outside.mkdir()
    link = base / "symlink_dir"
    os.symlink(outside, link)

    monkeypatch.setattr(Path, "cwd", classmethod(lambda cls: base))

    target = link / "escaped.flow"
    result_str = await server.start_proxy(dump_file=str(target))
    result = json.loads(result_str)

    assert result["status"] == "error"
    assert "Security Error" in result["message"]
    assert "Access denied" in result["message"]


@pytest.mark.asyncio
async def test_dump_file_allows_contained_path(tmp_path, monkeypatch):
    monkeypatch.setattr(Path, "cwd", classmethod(lambda cls: tmp_path))
    safe_file = tmp_path / "safe.flow"

    with patch.object(server.DumpMaster, "run"):
        result = await server.controller.start(dump_file=str(safe_file))
        assert "Started proxy" in result
        assert str(safe_file.resolve()) in result
        await server.controller.stop()


@pytest.mark.asyncio
async def test_dump_file_allows_append_mode_contained(tmp_path, monkeypatch):
    monkeypatch.setattr(Path, "cwd", classmethod(lambda cls: tmp_path))
    safe_file = tmp_path / "safe_append.flow"

    with patch.object(server.DumpMaster, "run"):
        result = await server.controller.start(dump_file=f"+{safe_file}")
        assert "Started proxy" in result
        await server.controller.stop()
