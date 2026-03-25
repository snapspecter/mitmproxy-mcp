import pytest
from types import SimpleNamespace

from mitmproxy_mcp.core import server


@pytest.mark.asyncio
async def test_generate_scraper_code_prefers_live_flow_body(monkeypatch):
    flow_id = "flow-live"

    def fake_get_flow_detail(fid):
        if fid != flow_id:
            return None
        return {
            "id": flow_id,
            "request": {
                "method": "POST",
                "url": "https://example.com/api/items",
                "headers": {"Content-Type": "application/json"},
                "body_preview": "db-preview-body",
            },
        }

    live_flow = SimpleNamespace(request=SimpleNamespace(content=b'{"source":"live"}'))

    monkeypatch.setattr(
        server.controller.recorder,
        "get_flow_detail",
        fake_get_flow_detail,
    )
    monkeypatch.setattr(
        server.controller.recorder,
        "get_live_flow",
        lambda fid: live_flow if fid == flow_id else None,
    )
    monkeypatch.setattr(
        server.controller.recorder.db,
        "get_flow_object",
        lambda fid: SimpleNamespace(body="db-body"),
    )

    code = await server.generate_scraper_code(flow_id)

    assert 'data_0 = "{\\"source\\":\\"live\\"}"' in code
    assert "db-body" not in code


@pytest.mark.asyncio
async def test_generate_scraper_code_uses_db_body(monkeypatch):
    flow_id = "flow-db"

    def fake_get_flow_detail(fid):
        if fid != flow_id:
            return None
        return {
            "id": flow_id,
            "request": {
                "method": "POST",
                "url": "https://example.com/api/items",
                "headers": {"Content-Type": "application/json"},
                "body_preview": "preview-body",
            },
        }

    monkeypatch.setattr(
        server.controller.recorder,
        "get_flow_detail",
        fake_get_flow_detail,
    )
    monkeypatch.setattr(
        server.controller.recorder,
        "get_live_flow",
        lambda fid: None,
    )
    monkeypatch.setattr(
        server.controller.recorder.db,
        "get_flow_object",
        lambda fid: SimpleNamespace(body="db-body"),
    )

    code = await server.generate_scraper_code(flow_id)

    assert 'data_0 = "db-body"' in code

@pytest.mark.asyncio
async def test_generate_scraper_code_requests_framework(monkeypatch):
    flow_id = "flow-requests"

    def fake_get_flow_detail(fid):
        if fid != flow_id:
            return None
        return {
            "id": flow_id,
            "request": {
                "method": "GET",
                "url": "https://example.com/api/items",
                "headers": {"Accept": "application/json"},
                "body_preview": None,
            },
        }

    monkeypatch.setattr(
        server.controller.recorder,
        "get_flow_detail",
        fake_get_flow_detail,
    )
    monkeypatch.setattr(
        server.controller.recorder,
        "get_live_flow",
        lambda fid: None,
    )
    monkeypatch.setattr(
        server.controller.recorder.db,
        "get_flow_object",
        lambda fid: SimpleNamespace(body=None),
    )

    code = await server.generate_scraper_code(flow_id, target_framework="requests")

    assert "import requests" in code
    assert "with requests.Session() as client:" in code
    assert "client.verify = False" in code
    assert "response_0 = client.request(" in code
    assert "timeout=30" in code


@pytest.mark.asyncio
async def test_generate_scraper_code_aiohttp_framework(monkeypatch):
    flow_id = "flow-aiohttp"

    def fake_get_flow_detail(fid):
        if fid != flow_id:
            return None
        return {
            "id": flow_id,
            "request": {
                "method": "POST",
                "url": "https://example.com/api/items",
                "headers": {"Accept": "application/json"},
                "body_preview": "some_body",
            },
        }

    monkeypatch.setattr(
        server.controller.recorder,
        "get_flow_detail",
        fake_get_flow_detail,
    )
    monkeypatch.setattr(
        server.controller.recorder,
        "get_live_flow",
        lambda fid: None,
    )
    monkeypatch.setattr(
        server.controller.recorder.db,
        "get_flow_object",
        lambda fid: SimpleNamespace(body="some_body"),
    )

    code = await server.generate_scraper_code(flow_id, target_framework="aiohttp")

    assert "import aiohttp" in code
    assert "async with aiohttp.ClientSession" in code
    assert "verify_ssl=False" in code
    assert 'async with client.request("POST",' in code
    assert "data=data_0" in code


@pytest.mark.asyncio
async def test_generate_scraper_code_playwright_framework(monkeypatch):
    flow_id = "flow-playwright"

    def fake_get_flow_detail(fid):
        if fid != flow_id:
            return None
        return {
            "id": flow_id,
            "request": {
                "method": "GET",
                "url": "https://example.com/ui/items",
                "headers": {"Accept": "text/html,application/xhtml+xml"},
                "body_preview": None,
            },
        }

    monkeypatch.setattr(
        server.controller.recorder,
        "get_flow_detail",
        fake_get_flow_detail,
    )
    monkeypatch.setattr(
        server.controller.recorder,
        "get_live_flow",
        lambda fid: None,
    )
    monkeypatch.setattr(
        server.controller.recorder.db,
        "get_flow_object",
        lambda fid: SimpleNamespace(body=None),
    )

    code = await server.generate_scraper_code(flow_id, target_framework="playwright")

    assert "from playwright.async_api import async_playwright" in code
    assert "browser = await p.chromium.launch(" in code
    # With text/html we should be using page.goto
    assert "response_0 = await page.goto(" in code

    # Test an API call (POST, application/json)
    def fake_get_flow_detail_api(fid):
        return {
            "id": fid,
            "request": {
                "method": "POST",
                "url": "https://example.com/api/items",
                "headers": {"Accept": "application/json"},
                "body_preview": "payload",
            },
        }

    monkeypatch.setattr(
        server.controller.recorder,
        "get_flow_detail",
        fake_get_flow_detail_api,
    )
    code_api = await server.generate_scraper_code(flow_id, target_framework="playwright")
    # With an API call it should use context.request.fetch
    assert "response_0 = await context.request.fetch(" in code_api


@pytest.mark.asyncio
async def test_generate_scraper_code_escapes_malicious_url(monkeypatch):
    """Regression test: URLs containing quotes must not break out of string
    literals in the generated code (code injection via crafted HTTP traffic)."""
    flow_id = "flow-inject"
    malicious_url = "https://evil.com'; import os; os.system('whoami'); #"

    def fake_get_flow_detail(fid):
        if fid != flow_id:
            return None
        return {
            "id": flow_id,
            "request": {
                "method": "GET",
                "url": malicious_url,
                "headers": {},
                "body_preview": None,
            },
        }

    monkeypatch.setattr(
        server.controller.recorder,
        "get_flow_detail",
        fake_get_flow_detail,
    )
    monkeypatch.setattr(
        server.controller.recorder,
        "get_live_flow",
        lambda fid: None,
    )
    monkeypatch.setattr(
        server.controller.recorder.db,
        "get_flow_object",
        lambda fid: None,
    )

    code = await server.generate_scraper_code(flow_id)

    # The generated code must be valid Python — compile() will raise
    # SyntaxError if the injected quotes broke out of a string literal.
    compile(code, "<generated>", "exec")

    # Executing the generated code must NOT run os.system — verify by
    # checking that 'os.system' never appears as a bare statement.
    # Split into lines and ensure no line starts with 'import os' or
    # 'os.system' outside of string literals.
    for line in code.splitlines():
        stripped = line.strip()
        assert not stripped.startswith("import os"), (
            f"Injection succeeded — bare 'import os' found: {line}"
        )
        assert not stripped.startswith("os.system"), (
            f"Injection succeeded — bare 'os.system' found: {line}"
        )
