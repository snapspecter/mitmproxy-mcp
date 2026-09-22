import asyncio

import pytest

from mitmproxy_mcp.core.server import MitmController


@pytest.mark.asyncio
async def test_proxy_task_failure_clears_state():
    controller = MitmController()
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


@pytest.mark.asyncio
async def test_proxy_task_clean_exit_clears_state():
    controller = MitmController()
    controller.running = True
    controller.master = object()

    async def finish():
        return None

    controller.proxy_task = asyncio.create_task(finish())
    controller.proxy_task.add_done_callback(controller._proxy_task_done)
    await asyncio.sleep(0)
    await asyncio.sleep(0)

    assert controller.running is False
    assert controller.master is None
    assert controller.proxy_task is None
