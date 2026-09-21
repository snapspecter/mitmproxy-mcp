"""Regression tests for the fixes found during security re-validation.

These cover the *wiring*, not just the helpers: the destination policy at the
replay/fuzz call sites, batch-path redaction, IPv4-mapped addresses, redirect
handling, staged imports, and header-template resolution.
"""

import json
from pathlib import Path

import pytest

from mitmproxy_mcp.core import server
from mitmproxy_mcp.core.netpolicy import check_destination
from mitmproxy_mcp.core.recorder import TrafficDB
from mitmproxy_mcp.core.server import _resolve_headers_json


@pytest.mark.parametrize(
    "url",
    [
        "http://[::ffff:127.0.0.1]/",
        "http://[::ffff:169.254.169.254]/latest/meta-data/",
        "http://[::ffff:10.0.0.5]/",
    ],
)
def test_ipv4_mapped_ipv6_is_blocked(url):
    assert check_destination(url, []) is not None


def _flow_detail(url):
    return {
        "id": "ssrf",
        "request": {"method": "GET", "url": url, "headers": {}, "body_preview": None},
        "response": {"status_code": 200, "headers": {}, "body_preview": "ok"},
    }


@pytest.mark.asyncio
async def test_replay_denies_off_scope_destination_before_any_request(monkeypatch):
    """check_destination at server.py must stop the call before the transport."""
    monkeypatch.setattr(
        server.controller.recorder, "get_flow_detail", lambda fid: _flow_detail("http://169.254.169.254/")
    )
    monkeypatch.setattr(
        server.controller.recorder.db, "get_flow_object", lambda fid: None
    )

    result = await server.replay_flow("ssrf")

    assert "Blocked by destination policy" in result


@pytest.mark.asyncio
async def test_replay_disables_redirects(monkeypatch):
    """A redirect would bypass the policy, so the request must not follow it."""
    captured = {}

    class FakeResponse:
        status_code = 200

    class FakeSession:
        def __init__(self, **kwargs):
            captured["session"] = kwargs

        async def __aenter__(self):
            return self

        async def __aexit__(self, *a):
            return False

        async def request(self, **kwargs):
            captured["request"] = kwargs
            return FakeResponse()

    monkeypatch.setattr(server.controller.recorder, "get_flow_detail", lambda fid: _flow_detail("https://api.example.com/x"))
    monkeypatch.setattr(server.controller.recorder.db, "get_flow_object", lambda fid: None)
    monkeypatch.setattr(server, "AsyncSession", FakeSession)

    server.controller.scope_config.allowed_domains = ["example.com"]
    try:
        result = await server.replay_flow("x")
    finally:
        server.controller.scope_config.allowed_domains = []

    assert "Replayed successfully" in result
    assert captured["request"]["allow_redirects"] is False


@pytest.mark.asyncio
async def test_fuzz_denies_off_scope_destination(monkeypatch):
    monkeypatch.setattr(
        server.controller.recorder, "get_flow_detail", lambda fid: _flow_detail("http://10.0.0.5/")
    )
    monkeypatch.setattr(server.controller.recorder.db, "get_flow_object", lambda fid: None)

    result = await server.fuzz_endpoint("f", "q", "query", "sqli")

    assert "Blocked by destination policy" in result


def test_batch_read_redacts_credentials(tmp_path):
    """inspect_flows (get_by_ids) must not leak Authorization/Cookie values."""
    from mitmproxy.test.tflow import tflow

    db = TrafficDB(db_path=str(tmp_path / "traffic.db"))
    flow = tflow()
    flow.request.url = "https://example.com/x"
    flow.request.headers["Authorization"] = "Bearer SUPERSECRET"
    flow.request.headers["Cookie"] = "session=SUPERSECRET"
    db.save_flow(flow)

    rows = db.get_by_ids([flow.id], ordered_headers=True)
    blob = json.dumps(rows)
    assert "SUPERSECRET" not in blob
    assert "<REDACTED>" in blob


def test_all_for_analysis_redacts_by_default(tmp_path):
    from mitmproxy.test.tflow import tflow

    db = TrafficDB(db_path=str(tmp_path / "traffic.db"))
    flow = tflow()
    flow.request.url = "https://example.com/x"
    flow.request.headers["Authorization"] = "Bearer SUPERSECRET"
    db.save_flow(flow)

    rows = db.get_all_for_analysis(redact=True)
    assert "SUPERSECRET" not in json.dumps(rows)
    rows_raw = db.get_all_for_analysis(redact=False)
    assert "SUPERSECRET" in json.dumps(rows_raw)


def test_staged_import_does_not_wipe_on_corrupt_file(tmp_path, monkeypatch):
    """A corrupt flow file must not clear existing traffic."""
    from mitmproxy.test.tflow import tflow

    root = tmp_path / "root"
    root.mkdir()
    monkeypatch.setenv(TrafficDB.IMPORT_PATH_ENV, str(root))

    db = TrafficDB(db_path=str(root / "traffic.db"))
    flow = tflow()
    flow.request.url = "https://example.com/keep"
    db.save_flow(flow)
    assert len(db.get_summary(limit=10)) == 1

    bad = root / "corrupt.mitm"
    bad.write_bytes(b"this is not a flow file")

    from mitmproxy.exceptions import FlowReadException

    with pytest.raises(FlowReadException):
        db.import_from_file(str(bad), append=False)

    # Existing traffic survived.
    assert len(db.get_summary(limit=10)) == 1


def test_headers_json_substitution_stays_inside_values():
    """A captured value containing a quote must not inject a new header."""
    vars_ = {"tok": 'x", "X-Evil": "1'}
    parsed, error = _resolve_headers_json('{"X-Foo": "$tok"}', vars_)
    assert error is None
    assert set(parsed) == {"X-Foo"}
    assert parsed["X-Foo"] == 'x", "X-Evil": "1'


def test_headers_json_rejects_crlf_from_variable():
    """CR/LF from a captured variable is stripped, so no header is injected."""
    parsed, error = _resolve_headers_json('{"X-Foo": "$tok"}', {"tok": "a\r\nX-Evil: 1"})
    assert error is None
    assert set(parsed) == {"X-Foo"}
    assert "\r" not in parsed["X-Foo"]
    assert "\n" not in parsed["X-Foo"]
