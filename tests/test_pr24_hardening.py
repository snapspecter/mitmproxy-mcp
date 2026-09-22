import asyncio
from types import SimpleNamespace

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


@pytest.mark.asyncio
async def test_stop_sets_stopping_before_instance_cleanup():
    controller = MitmController()
    controller.running = True

    class FakeInstance:
        async def stop(self):
            assert controller._stopping is True

    addon = SimpleNamespace(
        connections={},
        servers=SimpleNamespace(_instances={"proxy": FakeInstance()}),
    )
    master = SimpleNamespace(
        addons=SimpleNamespace(get=lambda name: addon if name == "proxyserver" else None),
        shutdown=lambda: None,
    )
    controller.master = master

    assert await controller.stop() == "Stopped the proxy."
    assert controller._stopping is False


@pytest.mark.asyncio
async def test_stop_retrieves_failed_task_exception():
    controller = MitmController()
    controller.running = True
    controller.master = SimpleNamespace(
        addons=SimpleNamespace(get=lambda name: None),
        shutdown=lambda: None,
    )

    async def fail():
        raise RuntimeError("shutdown race")

    task = asyncio.create_task(fail())
    await asyncio.sleep(0)
    controller.proxy_task = task

    assert await controller.stop() == "Stopped the proxy."
    assert task.done()
    assert controller.proxy_task is None
