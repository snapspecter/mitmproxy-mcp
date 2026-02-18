# mitmproxy MCP Server
A Model Context Protocol (MCP) server that transforms mitmproxy into a powerful toolset for AI agents. This allows LLMs (like Claude, GPT-4, or local models) to inspect, modify, and replay HTTP/HTTPS traffic in real-time.

## Why use this?
Standard "web search" or "fetch" tools are stateless and easily detected. mitmproxy-mcp provides:

* **Deep Debugging**: The agent can inspect full request/response cycles (headers, payloads, cookies) to identify why a frontend is failing or why an API is returning a `4xx/500` error.
* **API Reverse Engineering**: Let the LLM observe undocumented internal APIs, map out JSON schemas, and generate client libraries or documentation automatically.
* **Automated Security Testing**: Perform DAST (Dynamic Application Security Testing) by allowing the agent to inject payloads into specific parameters and analyze the response.
* **Live Interception**: Modify traffic on the fly: inject headers, mock responses for testing, or block tracking pixels to reduce noise.
* **Stealth Replay**: Uses `curl-cffi` to mimic Chrome/Safari TLS fingerprints, bypassing basic anti-bot measures that standard Python libraries trigger.

## Key Features

- **Lifecycle Control**: Start and stop the mitmproxy instance directly from the LLM.
- **Deep Inspection**: Capture full request/response cycles, including headers, bodies, and timing.
- **Precision Filtering**: Scope traffic to specific domains to keep the context window clean.
- **Active Interception**: Dynamic rules to inject headers, replace body content via regex, or block requests.
- **Stealth Replay**: Re-execute flows using `curl-cffi` to impersonate modern browser TLS fingerprints (e.g., Chrome).

## Quickstart

### Option 1: Using `uvx` (Recommended)
Add this to your MCP client configuration (e.g., Claude Desktop, Cursor, or AntiGravity):

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

## Installation

### Option 1: Global Install (with `uv`)

```bash
uv tool install mitmproxy-mcp

```

### Option 2: Docker (Isolated Environment)

```bash
# Build and run
docker build -t mitmproxy-mcp .
docker run -p 8080:8080 mitmproxy-mcp

```

### Option 3: Manual Pip Install

```bash
python -m venv venv
source venv/bin/activate
pip install mitmproxy-mcp

```

## Available Tools

### Lifecycle & Configuration

* `start_proxy(port=8080)`: Starts the mitmproxy server.
* `stop_proxy()`: Shuts down the proxy.
* `set_scope(allowed_domains)`: Filters recorded traffic (e.g., `["api.github.com", "example.com"]`).

### Inspection

* `get_traffic_summary(limit=20)`: Returns a list of recent network flows.
* `inspect_flow(flow_id)`: Provides full details and a `curl` equivalent for a specific flow.

### Modification & Interception

* `add_interception_rule(rule_id, action_type, ...)`:
* `action_type`: `inject_header`, `replace_body`, or `block`.
* `phase`: `request` or `response`.


* `set_global_header(key, value)`: Injects a header into every request.
* `clear_rules()`: Flushes all active interception rules.

### Replay

* `replay_flow(flow_id, method, headers_json, body)`: Re-sends a request with modifications using browser-grade impersonation.

## Programmatic Usage

Note: These are JSON-RPC calls sent by the MCP Host (Client). You do not need to type these manually in the terminal.

1. **Initialize the Proxy**:
`{"method": "tools/call", "params": {"name": "start_proxy", "arguments": {"port": 8080}}}`
2. **Intercept & Block**:
`{"method": "tools/call", "params": {"name": "add_interception_rule", "arguments": {"rule_id": "block-ads", "action_type": "block", "url_pattern": ".*analytics.*"}}}`
3. **Modify Response**:
`{"method": "tools/call", "params": {"name": "add_interception_rule", "arguments": {"rule_id": "mock-api", "action_type": "replace_body", "url_pattern": ".*user/profile.*", "action_value": "{\"name\": \"AI Agent\"}"}}}`

## Helpful Tips

* **Manage Context**: Use `set_scope` immediately. LLMs perform poorly when flooded with background OS telemetry.
* **Browser Setup**: Ensure your browser or application is configured to use the proxy (usually `localhost:8080`) and has the mitmproxy CA certificates installed for HTTPS inspection.
* **Stealth**: The `replay_flow` tool uses `curl-cffi` specifically to avoid being flagged as a bot by services that check TLS fingerprints.

## Development

```bash
git clone [https://github.com/snapspecter/mitmproxy-mcp.git](https://github.com/snapspecter/mitmproxy-mcp.git)
cd mitmproxy-mcp
uv sync
uv run pytest

```

**License:** MIT

**Author:** [SnapSpecter](https://github.com/snapspecter)

```
