import asyncio
import socket
import urllib.error
import urllib.request

import pytest

from mitmproxy_mcp.core import server
from mitmproxy_mcp.core.server import MitmController


def _free_port() -> int:
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


def _http_status(url: str) -> int:
    try:
        with urllib.request.urlopen(url, timeout=5) as resp:
            return resp.status
    except urllib.error.HTTPError as e:
        return e.code


def _port_is_free(port: int) -> bool:
    # SO_REUSEADDR skips TIME_WAIT from the test's requests, not a listener.
    with socket.socket() as s:
        s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        try:
            s.bind(("127.0.0.1", port))
        except OSError:
            return False
        return True


@pytest.fixture
def controller(monkeypatch):
    ctl = MitmController()
    monkeypatch.setattr(server, "controller", ctl)
    return ctl


@pytest.mark.asyncio
async def test_web_ui_serves_and_releases_port(controller):
    port, web_port = _free_port(), _free_port()

    result = await server.start_proxy(port=port, web=True, web_port=web_port)
    try:
        assert controller.running
        assert f"Web UI: http://127.0.0.1:{web_port}/?token=" in result
        await asyncio.sleep(0.5)
        assert await asyncio.to_thread(_http_status, controller.web_url) == 200
        no_token = f"http://127.0.0.1:{web_port}/"
        assert await asyncio.to_thread(_http_status, no_token) == 403
    finally:
        await controller.stop()

    assert controller.web_url is None
    assert _port_is_free(web_port)

    # A second start on the same ports must work once the first has stopped.
    result = await server.start_proxy(port=port, web=True, web_port=web_port)
    try:
        assert controller.running, result
    finally:
        await controller.stop()


@pytest.mark.asyncio
async def test_web_port_alone_turns_the_ui_on(controller):
    web_port = _free_port()
    result = await server.start_proxy(port=_free_port(), web_port=web_port)
    try:
        assert f":{web_port}/?token=" in result
    finally:
        await controller.stop()


@pytest.mark.asyncio
async def test_web_off_by_default(controller):
    result = await server.start_proxy(port=_free_port())
    try:
        assert "Web UI" not in result
        assert controller.web_url is None
    finally:
        await controller.stop()


@pytest.mark.asyncio
async def test_default_web_settings_apply(controller):
    controller.default_web = True
    controller.default_web_port = _free_port()
    result = await server.start_proxy(port=_free_port())
    try:
        assert f":{controller.default_web_port}/?token=" in result
    finally:
        await controller.stop()


@pytest.mark.asyncio
async def test_web_host_non_loopback_refused(controller):
    result = await server.start_proxy(port=_free_port(), web_host="0.0.0.0")
    assert "web UI to a non-loopback host" in result
    assert not controller.running


@pytest.mark.asyncio
async def test_proxy_host_non_loopback_refused(controller):
    result = await server.start_proxy(port=_free_port(), host="0.0.0.0")
    assert "proxy to a non-loopback host" in result
    assert not controller.running


@pytest.mark.asyncio
async def test_web_port_clash_with_proxy_refused(controller):
    port = _free_port()
    result = await server.start_proxy(port=port, web_port=port)
    assert "can't share" in result
    assert not controller.running


@pytest.mark.asyncio
async def test_busy_web_port_fails_fast(controller):
    with socket.socket() as busy:
        busy.bind(("127.0.0.1", 0))
        busy.listen()
        web_port = busy.getsockname()[1]
        result = await server.start_proxy(port=_free_port(), web_port=web_port)
    assert f"Couldn't start the web UI on 127.0.0.1:{web_port}" in result
    assert not controller.running
