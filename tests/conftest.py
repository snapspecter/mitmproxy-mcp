"""Shared test fixtures.

Importing ``mitmproxy_mcp.core.server`` creates a traffic database at import
time. These fixtures keep that database out of the repository working tree and
reset shared global state between tests.
"""

import os

import pytest


@pytest.fixture(autouse=True)
def isolated_traffic_db(tmp_path, monkeypatch):
    """Run every test in a temp cwd so no DB or stray file lands in the repo."""
    monkeypatch.chdir(tmp_path)
    # Recreate the schema in the temp cwd so queries never touch a stale path.
    from mitmproxy_mcp.core import server

    server.controller.recorder.db._init_db()
    yield tmp_path


@pytest.fixture(autouse=True)
def reset_controller_state():
    """Clear interception rules and session variables between tests."""
    from mitmproxy_mcp.core import server

    server.controller.interceptor.clear_rules()
    server.controller.session_variables.clear()
    server.controller.scope_config.allowed_domains = []
    yield
    server.controller.interceptor.clear_rules()
    server.controller.session_variables.clear()
    server.controller.scope_config.allowed_domains = []
