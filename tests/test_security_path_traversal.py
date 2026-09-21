import json
import os
from pathlib import Path

import pytest

from mitmproxy_mcp.core.recorder import TrafficDB
from mitmproxy_mcp.core.server import load_traffic_file

PROJECT_ROOT = Path(__file__).resolve().parents[1]


def _write_har(path: Path) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text('{"log": {"entries": []}}')


@pytest.mark.asyncio
async def test_path_traversal_denied(tmp_path):
    """A path outside the import root is refused."""
    outside = tmp_path / "outside.har"
    _write_har(outside)

    result = json.loads(await load_traffic_file(str(outside)))

    assert result["status"] == "error"
    assert "Security Error" in result["message"]


@pytest.mark.asyncio
async def test_sibling_prefix_is_not_a_bypass(tmp_path):
    """A sibling directory whose name extends the root must not pass."""
    sibling = PROJECT_ROOT.parent / (PROJECT_ROOT.name + "-evil")
    target = sibling / "secret.har"
    _write_har(target)
    try:
        result = json.loads(await load_traffic_file(str(target)))
        assert result["status"] == "error"
        assert "Security Error" in result["message"]
    finally:
        for child in sorted(sibling.rglob("*"), reverse=True):
            child.unlink() if child.is_file() else child.rmdir()
        sibling.rmdir()


@pytest.mark.asyncio
async def test_dotdot_traversal_denied(tmp_path):
    """Relative traversal escaping the root is refused."""
    result = json.loads(await load_traffic_file("../../../etc/passwd.har"))
    assert result["status"] == "error"


@pytest.mark.asyncio
async def test_symlinked_path_denied(tmp_path):
    """A symlink pointing outside the root is refused."""
    outside = tmp_path / "real.har"
    _write_har(outside)
    link = PROJECT_ROOT / "link_test.har"
    if link.exists() or link.is_symlink():
        link.unlink()
    os.symlink(outside, link)
    try:
        result = json.loads(await load_traffic_file(str(link)))
        assert result["status"] == "error"
    finally:
        if link.is_symlink():
            link.unlink()


@pytest.mark.asyncio
async def test_directory_path_denied(tmp_path):
    result = json.loads(await load_traffic_file(str(PROJECT_ROOT)))
    assert result["status"] == "error"


@pytest.mark.asyncio
async def test_non_har_extension_denied(tmp_path):
    txt = PROJECT_ROOT / "not_a_flow.txt"
    txt.write_text("hello")
    try:
        result = json.loads(await load_traffic_file(str(txt)))
        assert result["status"] == "error"
        assert "extension" in result["message"].lower()
    finally:
        txt.unlink()


@pytest.mark.asyncio
async def test_valid_path_allowed(isolated_traffic_db):
    """A .har inside the import root is accepted."""
    local_file = Path(isolated_traffic_db) / "test_safe_import.har"
    _write_har(local_file)
    # The import root is the project; use it explicitly via the env override.
    os.environ[TrafficDB.IMPORT_PATH_ENV] = str(isolated_traffic_db)
    try:
        result = json.loads(await load_traffic_file(str(local_file)))
        assert result["status"] == "ok"
    finally:
        del os.environ[TrafficDB.IMPORT_PATH_ENV]
        local_file.unlink()


def test_resolve_import_path_is_a_hard_gate():
    """The DB layer enforces the same rule independently of the tool layer."""
    with pytest.raises(PermissionError):
        TrafficDB.resolve_import_path("/etc/passwd.har")
