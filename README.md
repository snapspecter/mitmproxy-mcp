# Advanced mitmproxy MCP Server

A [Model Context Protocol (MCP)](https://github.com/modelcontextprotocol) server that wraps [mitmproxy](https://mitmproxy.org/). This tool allows AI assistants to inspect, modify, and replay HTTP/HTTPS traffic programmatically, enabling advanced debugging, API development, and testing workflows.

## Features

- **Start / Stop mitmproxy**: Allows the LLM to start and stop mitmproxy on demand.
- **Traffic Inspection**: Capture and inspect HTTP/HTTPS request and response details (headers, bodies, timing).
- **Traffic Filtering**: Scope traffic capture to specific domains to reduce noise.
- **Interception & Modification**: Dynamic rules to inject headers, replace body content (using regex), or block requests.
- **Request Replay**: Re-execute captured requests with modified parameters (method, headers, body) using `curl-cffi` for stealth (impersonating a modern browser).
- **Global Headers**: Easily set or remove global headers for all requests.

## Installation

### Option 1: Using `uv` (Recommended)

Quickly run without installing (using uvx):
```bash
uvx mitmproxy-mcp
```

Or install as a persistent tool:
```bash
uv tool install mitmproxy-mcp
```

### Option 2: Using `pip`

```bash
pip install mitmproxy-mcp
```

## Usage

### Starting the Server

Once installed, you can start the server directly:

```bash
mitmproxy-mcp
```

### Manual / Development Execution

If you are developing the package, you can run it derived from source:

```bash
# Install dependencies first
uv sync

# Run server
uv run mitmproxy-mcp
```

### Integration with MCP Clients

Add the server to your MCP client configuration (e.g., VS Code, Claude Desktop, AntiGravity).

**Example Configuration (Generic):**

```json
{
  "mcpServers": {
    "mitmproxy-mcp": {
      "command": "uvx",
      "args": ["mitmproxy-mcp"]
    }
  }
}
```

If you installed it via `pip` or want to point to a specific virtualenv:

```json
{
  "mcpServers": {
    "mitmproxy-mcp": 
      "command": "/path/to/venv/bin/mitmproxy-mcp",
      "args": []
    }
  }
}
```

## Available Tools

The following tools are exposed to the AI assistant:

### Lifecycle & Configuration

- `start_proxy(port=8080)`: Starts the mitmproxy server on the specified port.
- `stop_proxy()`: Stops the running proxy server.
- `set_scope(allowed_domains)`: updates the list of domains to record traffic for (e.g., `["example.com", "api.test.com"]`). Empty list records everything (subject to extension filtering).

### Inspection

- `get_traffic_summary(limit=20)`: Returns a list of recent flows with basic info (ID, URL, method, status, timestamp).
- `inspect_flow(flow_id)`: Returns full details for a specific flow, including headers and body previews. Also generates a `curl` command equivalent.

### Modification & Interception

- `set_global_header(key, value)`: Injects a header into all requests.
- `remove_global_header(key)`: Removes a previously set global header.
- `add_interception_rule(rule_id, action_type, ...)`: Adds a complex rule.
  - `action_type`: `inject_header`, `replace_body`, or `block`.
  - `phase`: `request` or `response`.
  - Can filter by `url_pattern` and `method`.
- `list_rules()`: Lists active interception rules.
- `clear_rules()`: Removes all interception rules.

### Replay

- `replay_flow(flow_id, method, headers_json, body)`: Re-sends a request based on a previous flow.
  - Uses `curl-cffi` to mimic a Chrome browser for stealth.
  - Useful for testing API endpoints with modified payloads or authentication.
    
    

> Note: Some functions (inspect/replay/detect) require captured flow IDs, which are available only after the proxy has processed traffic.

## Author

**SnapSpecter**



## Quick Start for IDE / Chat Interface:

Ask the LLM to start the mitmproxy-mcp server, then tell it add a set of rules related to the domain you are working with, it should take it from there.

## If using this programatically, heres a basic workflow:

1. **Start the proxy** (defaults to port 8080):
- `mcp_mitmproxy-mcp_start_proxy({ port: 8080 })`
2. **Add a rule** (example: block example.com):
- `mcp_mitmproxy-mcp_add_interception_rule({ rule_id: "block-example", action_type: "block", url_pattern: ".*example.com.*" })`
3. **List rules** to verify:
- `mcp_mitmproxy-mcp_list_rules()`
4. **Set a global header** (optional):
- `mcp_mitmproxy-mcp_set_global_header({ key: "X-Debug", value: "1" })`
5. **Clear rules / remove headers** when done:
- `mcp_mitmproxy-mcp_clear_rules()`

- `mcp_mitmproxy-mcp_remove_global_header({ key: "X-Debug" })`
6. **Stop the proxy**:
- `mcp_mitmproxy-mcp_stop_proxy()`

## Tips

- Keep `rule_id` unique per rule.

- Use `url_pattern` as a regex to target traffic; `phase` defaults to `request` if omitted.

- Replay/inspect/detect operations need valid `flow_id` values captured by the proxy.

- If a port is busy, start the proxy on a different `port` value.

- Set rules/scope, if using it unfiltered it can easily flood the LLM with too much noise.
