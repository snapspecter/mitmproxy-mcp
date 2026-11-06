import json

import pytest

from mitmproxy_mcp.core import server


def _accepts_null(prop: dict) -> bool:
    if prop.get("type") == "null":
        return True
    if isinstance(prop.get("type"), list) and "null" in prop["type"]:
        return True
    return any(_accepts_null(option) for option in prop.get("anyOf", []))


@pytest.mark.asyncio
async def test_every_null_default_argument_accepts_null():
    """An argument whose schema advertises "default": null must accept null."""
    tools = await server.mcp.list_tools()
    offenders = [
        f"{tool.name}.{name}"
        for tool in tools
        for name, prop in tool.inputSchema.get("properties", {}).items()
        if "default" in prop and prop["default"] is None and not _accepts_null(prop)
    ]
    assert not offenders, f"default is null but type rejects null: {offenders}"


@pytest.mark.asyncio
async def test_explicit_null_passes_argument_validation(monkeypatch):
    class StubRecorder:
        def search(self, query, domain, method, limit):
            return [{"query": query, "domain": domain, "method": method}]

    monkeypatch.setattr(server.controller, "recorder", StubRecorder())

    result = await server.mcp.call_tool(
        "search_traffic", {"query": None, "domain": None, "method": None}
    )
    content = result[0] if isinstance(result, tuple) else result
    assert json.loads(content[0].text) == [{"query": None, "domain": None, "method": None}]
