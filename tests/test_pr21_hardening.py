import asyncio

import pytest

from mitmproxy_mcp.core import server


def test_validate_listen_port():
    server._validate_listen_port(1)
    server._validate_listen_port(65535)

    for value in (0, 65536, "8080", True):
        with pytest.raises(ValueError):
            server._validate_listen_port(value)


def test_parse_listen_port():
    assert server._parse_port("8080") == 8080
    with pytest.raises(ValueError):
        server._parse_port("not-a-port")


def test_remote_bind_requires_opt_in():
    assert server._is_loopback_host("127.0.0.1")
    assert server._is_loopback_host("localhost")
    assert not server._is_loopback_host("0.0.0.0")
    assert not server._is_loopback_host("example.test")


@pytest.mark.asyncio
async def test_proxy_task_failure_clears_state():
    controller = server.MitmController()
    controller.running = True
    controller.master = object()

    async def fail():
        raise RuntimeError("bind failed")

    controller.proxy_task = asyncio.create_task(fail())
    controller.proxy_task.add_done_callback(controller._proxy_task_done)
    await asyncio.sleep(0)
    await asyncio.sleep(0)

    assert controller.running is False
    assert controller.master is None
    assert controller.proxy_task is None
