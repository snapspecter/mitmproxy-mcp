import pytest
import json
from mitmproxy_mcp.core.server import list_tools


@pytest.mark.asyncio
async def test_list_tools():
    result = await list_tools()
    tools = json.loads(result)

    # Verify we get a list
    assert isinstance(tools, list)

    # Check for presence of core tools
    tool_names = [t["name"] for t in tools]
    assert "start_proxy" in tool_names
    assert "stop_proxy" in tool_names
    assert "list_tools" in tool_names

    # Ensure newly added tools are included in tool discovery
    expected_new_tools = {
        "extract_from_flow",
        "set_session_variable",
        "extract_session_variable",
        "fuzz_endpoint",
        "export_openapi_spec",
        "get_api_patterns",
        "detect_auth_pattern",
        "generate_scraper_code",
    }
    missing_tools = expected_new_tools - set(tool_names)
    assert not missing_tools, (
        "Missing tools in list_tools output: "
        f"{sorted(missing_tools)}"
    )

    # Check structure of a tool entry
    list_tool = next(t for t in tools if t["name"] == "list_tools")
    assert (
        list_tool["description"]
        == "List all available tools with their descriptions."
    )
    assert "input_schema" in list_tool
