import json
from pathlib import Path

import pytest

from mitmproxy_mcp.core import server


@pytest.fixture
def import_stub(monkeypatch):
    monkeypatch.setattr(
        server.controller.recorder.db,
        "import_from_file",
        lambda *args, **kwargs: {"imported": 0, "skipped": 0, "errors": []},
    )


@pytest.mark.asyncio
async def test_allows_nested_path_and_base_directory(tmp_path, monkeypatch, import_stub):
    monkeypatch.setattr(Path, "cwd", classmethod(lambda cls: tmp_path))
    nested = tmp_path / "captures" / "capture.har"
    nested.parent.mkdir()
    nested.touch()
    base_file = tmp_path / "capture.har"
    base_file.touch()

    for path in (nested, base_file):
        result = json.loads(await server.load_traffic_file(str(path)))
        assert result["status"] == "ok"


@pytest.mark.asyncio
async def test_denies_sibling_prefix(tmp_path, monkeypatch):
    base = tmp_path / "project"
    sibling = tmp_path / "project-evil" / "capture.har"
    sibling.parent.mkdir(parents=True)
    sibling.touch()
    monkeypatch.setattr(Path, "cwd", classmethod(lambda cls: base))

    result = json.loads(await server.load_traffic_file(str(sibling)))

    assert result["status"] == "error"
    assert "Access denied" in result["message"]


@pytest.mark.asyncio
async def test_denies_parent_traversal(tmp_path, monkeypatch):
    base = tmp_path / "project"
    outside = tmp_path / "capture.har"
    outside.touch()
    monkeypatch.setattr(Path, "cwd", classmethod(lambda cls: base))

    result = json.loads(await server.load_traffic_file("../capture.har"))

    assert result["status"] == "error"
    assert "Access denied" in result["message"]


@pytest.mark.asyncio
async def test_denies_absolute_path_outside_base(tmp_path, monkeypatch):
    base = tmp_path / "project"
    outside = tmp_path / "outside.har"
    outside.touch()
    monkeypatch.setattr(Path, "cwd", classmethod(lambda cls: base))

    result = json.loads(await server.load_traffic_file(str(outside)))

    assert result["status"] == "error"
    assert "Access denied" in result["message"]


@pytest.mark.asyncio
async def test_denies_symlink_escape(tmp_path, monkeypatch):
    base = tmp_path / "project"
    base.mkdir()
    outside = tmp_path / "outside.har"
    outside.touch()
    link = base / "capture.har"
    link.symlink_to(outside)
    monkeypatch.setattr(Path, "cwd", classmethod(lambda cls: base))

    result = json.loads(await server.load_traffic_file(str(link)))

    assert result["status"] == "error"
    assert "Access denied" in result["message"]
