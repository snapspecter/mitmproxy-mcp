# Advanced mitmproxy MCP Server

A Model Context Protocol (MCP) server that wraps [mitmproxy](https://mitmproxy.org/) and exoses it as a tool to MCP clients. This tool allows AI assistants and GenAI tools to inspect, modify, and replay HTTP/HTTPS traffic programmatically, enabling advanced debugging, API development, and testing workflows.

## Features

- **Start / Stop mitmproxy**: Allows the LLM to start and stop mitmproxy as needed.
- **Traffic Inspection**: Capture and inspect HTTP/HTTPS request and response details (headers, bodies, timing).
- **Traffic Filtering**: Scope traffic capture to specific domains to reduce noise.
- **Interception & Modification**: Dynamic rules to inject headers, replace body content (using regex), or block requests.
- **Request Replay**: Re-execute captured requests with modified parameters (method, headers, body) using `curl-cffi` for stealth (impersonating a modern browser).
- **Global Headers**: Easily set or remove global headers for all requests.

## Installation

### Option 1: Using `uv` (Easy)
Use it without installing (using uvx):
```bash
uvx mitmproxy-mcp
```

Or install as a persistent tool:
```bash
uv tool install mitmproxy-mcp
```

### Option 2: Using Docker (Recommended for Isolation)
```bash
# Build and run with docker compose
docker compose up -d

# Or build manually
docker build -t mitmproxy-mcp .
docker run -p 8080:8080 mitmproxy-mcp
```

### Option 3: Using `pip` (Make sure to use a virtualenv)
```bash
pip install mitmproxy-mcp
```

## Usage

### Starting the Server
Once installed, you can start the server directly:

```bash
mitmproxy-mcp
```

### Manual / Development 

If you plan on making any changes to the code, or just want to run it from source, you can run it like this:

### Prerequisites

- [uv](https://github.com/astral-sh/uv) (for dependency management, recommended)

```bash
# Clone the repository
git clone https://github.com/snapspecter/mitmproxy-mcp.git
cd mitmproxy-mcp
# Installs dependencies, creates .venv directory, etc:
uv sync
# Run tests
uv run pytest
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
The following tools are exposed to via the MCP server:

#### Lifecycle & Configuration
- `start_proxy(port=8080)`: Starts the mitmproxy server on the specified port.
- `stop_proxy()`: Stops the running proxy server.
- `set_scope(allowed_domains)`: updates the list of domains to record traffic for (e.g., `["example.com", "api.test.com"]`). Empty list records everything (subject to extension filtering).

#### Inspection
- `get_traffic_summary(limit=20)`: Returns a list of recent flows with basic info (ID, URL, method, status, timestamp).
- `inspect_flow(flow_id)`: Returns full details for a specific flow, including headers and body previews. Also generates a `curl` command equivalent.

#### Modification & Interception
- `set_global_header(key, value)`: Injects a header into all requests.
- `remove_global_header(key)`: Removes a previously set global header.
- `add_interception_rule(rule_id, action_type, ...)`: Adds a complex rule.
  - `action_type`: `inject_header`, `replace_body`, or `block`.
  - `phase`: `request` or `response`.
  - Can filter by `url_pattern` and `method`.
- `list_rules()`: Lists active interception rules.
- `clear_rules()`: Removes all interception rules.

#### Replay
- `replay_flow(flow_id, method, headers_json, body)`: Re-sends a request based on a previous flow.
  - Uses `curl-cffi` to mimic a Chrome browser for stealth.
  - Useful for testing API endpoints with modified payloads or authentication.
    

> Note: Some functions (inspect/replay/detect) require captured flow IDs, which are available only after the proxy has processed traffic.

## Quick Start

### IDE / Chat Interface:

Ask the LLM to start the mitmproxy-mcp server, then tell it add a set of rules related to the domain you are working with, it should take it from there.

### Using it programatically:

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

To make it easier for the LLM to work with the data returned by the proxy, and to keep API costs down, consider following these tips:
- Keep `rule_id` unique per rule.
- Use `url_pattern` as a regex to target traffic; `phase` defaults to `request` if omitted.
- Replay/inspect/detect operations need valid `flow_id` values captured by the proxy.
- Set rules/scope, espically if you plan to do the navigating for the LLM in your default browser, as it will capture all traffic, which can be a lot.
- If you're using port 8080 for something else, you can start the proxy on a different port using the `port` parameter.

## License
MIT

## Author
**SnapSpecter**
