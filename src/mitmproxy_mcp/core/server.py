import asyncio
import contextlib
import ipaddress
import logging
import os
import sys
import json
from pathlib import Path
from collections import Counter
from typing import List, Dict, Any, Optional, Tuple
from urllib.parse import urlparse, parse_qs, urlencode, parse_qsl
import re
import re2

import structlog

from mcp.server.fastmcp import FastMCP
from mitmproxy import exceptions
from mitmproxy import master as mitm_master
from mitmproxy import options
from mitmproxy.tools.dump import DumpMaster
from mitmproxy.tools.web.master import WebMaster
import tornado.httpserver
from tornado.log import access_log as tornado_access_log
from curl_cffi.requests import AsyncSession
from jsonpath_ng import parse as parse_jsonpath
from bs4 import BeautifulSoup

from ..models import ScopeConfig, InterceptionRule
from .scope import ScopeManager
from .recorder import TrafficRecorder
from .interceptor import TrafficInterceptor
from .generation import normalize_scraper_flows, render_scraper_code

# Configure structlog
structlog.configure(
    processors=[
        structlog.processors.TimeStamper(fmt="iso"),
        structlog.stdlib.add_log_level,
        structlog.processors.JSONRenderer(),
    ],
    context_class=dict,
    logger_factory=structlog.stdlib.LoggerFactory(),
)

# Configure standard logging to output the JSON string as-is
logging.basicConfig(
    format="%(message)s",
    level=logging.INFO,
    stream=sys.stderr,
)

logger = structlog.get_logger()


def _log_web_request(handler) -> None:
    """Tornado's access log minus the query string, which carries the UI token."""
    status = handler.get_status()
    if status < 400:
        log = tornado_access_log.info
    elif status < 500:
        log = tornado_access_log.warning
    else:
        log = tornado_access_log.error
    req = handler.request
    log("%d %s %s (%s) %.2fms", status, req.method, req.path, req.remote_ip,
        1000.0 * req.request_time())


class McpWebMaster(WebMaster):
    """WebMaster that keeps its HTTP server, so stop() can free web_port."""

    http_server: Optional[tornado.httpserver.HTTPServer] = None

    def __init__(self, opts: options.Options, with_termlog: bool = True):
        super().__init__(opts, with_termlog=with_termlog)
        self.app.settings["log_function"] = _log_web_request

    async def running(self):
        # Mirrors WebMaster.running(), which drops the server on the floor.
        self.http_server = tornado.httpserver.HTTPServer(self.app, max_buffer_size=2**32)
        self.http_server.listen(self.options.web_port, self.options.web_host)
        logger.info("web_ui_listening", host=self.options.web_host, port=self.options.web_port)
        return await mitm_master.Master.running(self)


class MitmController:
    def __init__(self, dump_file: Optional[str] = None):
        self.master: Optional[DumpMaster | McpWebMaster] = None
        self.proxy_task: Optional[asyncio.Task] = None
        self.scope_config = ScopeConfig()
        self.scope_manager = ScopeManager(self.scope_config)
        self.recorder = TrafficRecorder(self.scope_manager)
        self.interceptor = TrafficInterceptor()
        self.running = False
        self.port = 8080
        self.session_variables = {}
        self.dump_file = dump_file
        self.cli_upstream_proxy: Optional[str] = None
        self.default_port = 8080
        self.default_host = "127.0.0.1"
        self.default_web = False
        self.default_web_port = 8081
        self.default_web_host = "127.0.0.1"
        self.web_password: Optional[str] = None
        self.web_url: Optional[str] = None
        self.auto_start = False
        self.allow_remote_bind = False
        self._stopping = False

    def _get_verify_param(self, verify_override: Optional[bool] = None) -> Any:
        if verify_override is not None:
            return verify_override

        cert_path = os.path.expanduser("~/.mitmproxy/mitmproxy-ca-cert.pem")
        if os.path.exists(cert_path):
            return cert_path

        return True

    async def start(
        self,
        port: int = 8080,
        host: str = "127.0.0.1",
        dump_file: Optional[str] = None,
        upstream_proxy: Optional[str] = None,
        web: bool = False,
        web_port: int = 8081,
        web_host: str = "127.0.0.1",
    ):
        if self.running:
            return "MITM is already running."

        _validate_listen_port(port)
        if web:
            _validate_listen_port(web_port)
        if not self.allow_remote_bind and not _is_loopback_host(host):
            return (
                "Refusing to bind the proxy to a non-loopback host without "
                "explicit remote-bind authorization."
            )
        if web and not self.allow_remote_bind and not _is_loopback_host(web_host):
            return (
                "Refusing to bind the web UI to a non-loopback host without "
                "explicit remote-bind authorization."
            )
        if web and (host, port) == (web_host, web_port):
            return f"The proxy and the web UI can't share {host}:{port}."

        self.port = port
        opts = options.Options(listen_host=host, listen_port=port)

        up_proxy = upstream_proxy or self.cli_upstream_proxy
        if up_proxy:
            opts.update(mode=f"upstream:{up_proxy}")
            logger.info("upstream_proxy_configured", url=up_proxy)

        if web:
            self.master = McpWebMaster(opts, with_termlog=False)
            # These options only exist once WebMaster has loaded its addons.
            opts.update(web_port=web_port, web_host=web_host, web_open_browser=False)
            if self.web_password:
                try:
                    opts.update(web_password=self.web_password)
                except exceptions.OptionsError as e:
                    self.master = None
                    logger.error("web_password_invalid", error=str(e))
                    return f"Couldn't start the web UI: {e}"
        else:
            self.master = DumpMaster(
                opts,
                with_termlog=False,
                with_dumper=False,
            )
        self.master.addons.add(self.recorder)
        self.master.addons.add(self.interceptor)

        save_path = dump_file or self.dump_file
        if save_path:
            try:
                resolved_target = _validate_contained_path(save_path, allow_append_prefix=True)
                save_path_opts = f"+{resolved_target}" if save_path.startswith("+") else str(resolved_target)
            except PermissionError as e:
                logger.error("proxy_start_path_denied", path=save_path, error=str(e))
                return json.dumps({
                    "status": "error",
                    "message": str(e),
                })
            except Exception as e:
                logger.error("proxy_start_path_invalid", path=save_path, error=str(e))
                return json.dumps({
                    "status": "error",
                    "message": f"Invalid path: {str(e)}",
                })
            opts.update(save_stream_file=save_path_opts)
            logger.info("flow_dump_enabled", path=save_path_opts)

        # pre-check: fail fast if the port is taken. mitmproxy's master.run() dies
        # async with SystemExit on bind failure, which would otherwise leave a false
        # "Started" + running=True. A synchronous probe bind is deterministic.
        import socket

        binds = [("proxy", host, port)]
        if web:
            binds.append(("web UI", web_host, web_port))
        for label, bind_host, bind_port in binds:
            family = socket.AF_INET6 if ":" in bind_host else socket.AF_INET
            probe = socket.socket(family, socket.SOCK_STREAM)
            if os.name != "nt":
                # As the real listeners do: TIME_WAIT from a stopped run
                # passes, a live listener still fails the bind.
                probe.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            try:
                probe.bind((bind_host, bind_port))
            except OSError as e:
                self.master = None
                logger.error("proxy_start_failed", host=bind_host, port=bind_port, error=str(e))
                return f"Couldn't start the {label} on {bind_host}:{bind_port}: {e}"
            finally:
                probe.close()

        self._stopping = False
        self.proxy_task = asyncio.create_task(self.master.run())
        self.proxy_task.add_done_callback(self._proxy_task_done)
        self.running = True
        self.web_url = self.master.web_url if web else None
        logger.info("proxy_started", host=host, port=port, web=web)
        msg = f"Started proxy on port {port}"
        if save_path:
            msg += f", dumping flows to {save_path}"
        if self.web_url:
            msg += f". Web UI: {self.web_url}"
            if self.web_password:
                msg += " (protected by the configured web password)"
        return msg

    def _proxy_task_done(self, task: asyncio.Task) -> None:
        """Observe unexpected proxy task failures and clear stale state."""
        if self._stopping:
            try:
                task.exception()
            except asyncio.CancelledError:
                pass
            return
        try:
            error = task.exception()
        except asyncio.CancelledError:
            error = None
        http_server = getattr(self.master, "http_server", None)
        if http_server:
            http_server.stop()
        self.running = False
        self.master = None
        self.proxy_task = None
        self.web_url = None
        if error is not None:
            logger.error("proxy_task_failed", error=str(error))
        else:
            logger.warning("proxy_stopped_unexpectedly")

    async def stop(self):
        if not self.running or not self.master:
            return "The proxy isn't running right now."
        self._stopping = True
        master = self.master
        proxy_task = self.proxy_task
        try:
            # Explicitly stop all server instances to release the listening port
            # and close all active connections (keepalive connections otherwise persist)
            ps_addon = master.addons.get("proxyserver")
            if ps_addon:
                for handler in list(ps_addon.connections.values()):
                    try:
                        for transport_io in list(handler.transports.values()):
                            if transport_io.writer and not transport_io.writer.is_closing():
                                transport_io.writer.close()
                    except Exception:
                        pass
                for instance in list(ps_addon.servers._instances.values()):
                    try:
                        await instance.stop()
                    except Exception:
                        pass
                ps_addon.servers._instances.clear()
            http_server = getattr(master, "http_server", None)
            if http_server:
                http_server.stop()
                try:
                    await asyncio.wait_for(http_server.close_all_connections(), timeout=5.0)
                except asyncio.TimeoutError:
                    logger.warning("web_ui_connections_not_closed")
            master.shutdown()
            if proxy_task:
                done, _ = await asyncio.wait({proxy_task}, timeout=5.0)
                if not done:
                    proxy_task.cancel()
                    try:
                        await proxy_task
                    except asyncio.CancelledError:
                        pass
                else:
                    try:
                        proxy_task.exception()
                    except asyncio.CancelledError:
                        pass
        finally:
            self.proxy_task = None
            self.running = False
            self.master = None
            self.web_url = None
            self._stopping = False
        logger.info("proxy_stopped")
        return "Stopped the proxy."

    async def replay_request(
        self,
        flow_id: str,
        method: Optional[str] = None,
        headers: Optional[Dict[str, str]] = None,
        body: Optional[str] = None,
        timeout: float = 30.0,
    ) -> str:
        """
        Re-executes captured request using curl_cffi
        """
        # Fetch flow details from DB (dict)
        flow_data = self.recorder.get_flow_detail(flow_id)
        if not flow_data:
            return "Couldn't find that flow"

        original_request = flow_data["request"]
        target_url = original_request["url"]
        target_method = method if method else original_request["method"]

        target_headers = dict(original_request["headers"])
        target_headers.pop("Host", None)
        target_headers.pop("Content-Length", None)
        target_headers.pop("Content-Encoding", None)

        if headers:
            target_headers.update(headers)

        target_content = None
        if body is not None:
            target_content = body
        else:
            # Prefer full body from DB; fall back to preview
            flow_obj = self.recorder.db.get_flow_object(flow_id)
            if flow_obj and flow_obj.body is not None:
                target_content = flow_obj.body
            else:
                target_content = original_request.get("body_preview")
            if not target_content:
                target_content = None

        logger.info(
            "replay_request",
            flow_id=flow_id,
            method=target_method,
            url=target_url,
            mode="stealth",
        )

        proxy_url = f"http://127.0.0.1:{self.port}"

        try:
            async with AsyncSession(
                impersonate="chrome120",
                proxies={
                    "http": proxy_url,
                    "https": proxy_url,
                },
                verify=self._get_verify_param(),
                timeout=timeout,
            ) as client:
                request_kwargs = {
                    "method": target_method,
                    "url": target_url,
                    "headers": target_headers,
                }
                if isinstance(target_content, str):
                    request_kwargs["data"] = target_content
                elif isinstance(target_content, bytes):
                    request_kwargs["data"] = target_content

                response = await client.request(**request_kwargs)

            return f"Replayed successfully! (Status: {response.status_code}). Check the traffic summary for the new flow."
        except Exception as e:
            logger.error(f"Replay failed: {e}")
            return f"That didn't work: {str(e)}"


# Global Controller Instance
controller = MitmController()


def _validate_contained_path(
    path_str: str,
    base_dir: Optional[Path] = None,
    allow_append_prefix: bool = False,
) -> Path:
    if not path_str or not isinstance(path_str, str):
        raise ValueError("path cannot be empty")

    raw = path_str
    if allow_append_prefix and raw.startswith("+"):
        raw = raw[1:]

    if not raw:
        raise ValueError("path cannot be empty")

    base = (base_dir or Path.cwd()).resolve()
    target = Path(raw).resolve()

    if not target.is_relative_to(base):
        raise PermissionError(
            f"Security Error: Access denied to {path_str}. Path must be within the project directory."
        )
    return target


def _validate_listen_port(port: int) -> None:
    if isinstance(port, bool) or not isinstance(port, int) or not 1 <= port <= 65535:
        raise ValueError("listen port must be an integer between 1 and 65535")


def _is_loopback_host(host: str) -> bool:
    if host.lower() == "localhost":
        return True
    try:
        return ipaddress.ip_address(host).is_loopback
    except ValueError:
        return False


@contextlib.asynccontextmanager
async def _lifespan(_server: FastMCP):
    """Auto-start the proxy on boot when --auto-start / MITMPROXY_AUTO_START is set."""
    try:
        if getattr(controller, "auto_start", False) and not controller.running:
            result = await controller.start(
                port=controller.default_port,
                host=controller.default_host,
                web=controller.default_web,
                web_port=controller.default_web_port,
                web_host=controller.default_web_host,
            )
            if not controller.running:
                raise RuntimeError(f"Proxy auto-start failed: {result}")
            logger.info("auto_start", result=result)
        yield
    finally:
        if controller.running:
            await controller.stop()


mcp = FastMCP("Mitmproxy Manager", lifespan=_lifespan)

# --- MCP Tools ---


@mcp.tool()
async def start_proxy(
    port: Optional[int] = None,
    host: Optional[str] = None,
    dump_file: Optional[str] = None,
    upstream_proxy: Optional[str] = None,
    web: Optional[bool] = None,
    web_port: Optional[int] = None,
    web_host: Optional[str] = None,
) -> str:
    """
    Start the mitmproxy instance.
    Args:
        port: Port to listen on. Omit to use the server's configured default
            (--port / MITMPROXY_PORT, else 8080).
        host: Host to listen on. Omit to use the server's configured default
            (--host / MITMPROXY_HOST, else 127.0.0.1). A non-loopback host needs
            --allow-remote-bind.
        dump_file: Optional file path to save raw mitmproxy .flow data.
            Prefix with + to append to an existing file.
        upstream_proxy: Optional upstream proxy URL (e.g., 'http://user:pass@proxy:port').
        web: Also serve the mitmweb UI. Omit to use the server's default
            (--web / MITMPROXY_WEB, else off). Passing web_port or web_host
            turns it on. The result carries the UI URL with its access token,
            or without one when --web-password / MITMPROXY_WEB_PASSWORD is set.
        web_port: Web UI port. Omit for --web-port / MITMPROXY_WEB_PORT, else 8081.
        web_host: Web UI host. Omit for --web-host / MITMPROXY_WEB_HOST, else
            127.0.0.1. A non-loopback host needs --allow-remote-bind.
    """
    if web is None:
        web = controller.default_web or web_port is not None or web_host is not None
    try:
        return await controller.start(
            port=port if port is not None else controller.default_port,
            host=host if host is not None else controller.default_host,
            dump_file=dump_file,
            upstream_proxy=upstream_proxy,
            web=web,
            web_port=web_port if web_port is not None else controller.default_web_port,
            web_host=web_host if web_host is not None else controller.default_web_host,
        )
    except Exception as e:
        logger.error("proxy_start_failed", error=str(e))
        return f"Couldn't start the proxy: {str(e)}"


@mcp.tool()
async def stop_proxy() -> str:
    return await controller.stop()


@mcp.tool()
async def set_scope(allowed_domains: List[str]) -> str:
    controller.scope_manager.update_domains(allowed_domains)
    if allowed_domains:
        domains_str = ", ".join(allowed_domains)
    else:
        domains_str = "everything"
    return f"Updated. Now tracking: {domains_str}"


@mcp.tool()
async def set_global_header(key: str, value: str) -> str:
    rule_id = f"global_{key.lower()}"
    rule = InterceptionRule(
        id=rule_id,
        url_pattern=".*",
        resource_type="request",
        action_type="inject_header",
        key=key,
        value=value,
    )
    controller.interceptor.add_rule(rule)
    return f"Set global header: {key} = {value}"


@mcp.tool()
async def remove_global_header(key: str) -> str:
    rule_id = f"global_{key.lower()}"
    controller.interceptor.remove_rule(rule_id)
    return f"Removed global header: {key}"


@mcp.tool()
async def get_traffic_summary(limit: int = 20) -> str:
    flows = controller.recorder.get_flow_summary(limit)
    return json.dumps(flows, indent=2)


@mcp.tool()
async def inspect_flow(flow_id: str, full_body: bool = False) -> str:
    """
    Get full details of a captured flow.
    Args:
        flow_id: The ID of the captured flow
        full_body: If True, return full request body instead of 2000-char preview
    """
    logger.debug("inspect_flow", flow_id=flow_id)
    data = controller.recorder.get_flow_detail(flow_id)
    if not data:
        return "Couldn't find that flow."
    if full_body and data.get("request"):
        flow_obj = controller.recorder.db.get_flow_object(flow_id)
        if flow_obj and flow_obj.body is not None:
            data["request"]["body"] = flow_obj.body
            data["request"].pop("body_preview", None)
    return json.dumps(data, indent=2)


@mcp.tool()
async def inspect_flows(
    flow_ids: str,
    fields: str = None,
    full_body: bool = False,
) -> str:
    """
    Batch inspect multiple flows in one call. Reduces context usage vs
    calling inspect_flow N times.
    Args:
        flow_ids: Comma-separated list of flow IDs to inspect
        fields: Comma-separated list of DB columns to select.
            e.g. "id,url,method,request_headers,request_body" to skip
            response data. Default: all columns.
        full_body: If True, return full request body instead of preview
    """
    ids = [fid.strip() for fid in flow_ids.split(",") if fid.strip()]
    columns = [c.strip() for c in fields.split(",")] if fields else None
    derived_fields = set()
    if columns:
        derived_fields = {c for c in columns if c in {"content_type", "response_content_type"}}
        if derived_fields:
            if "response_headers" not in columns:
                columns.append("response_headers")
            # Remove derived field names before passing to DB query
            columns = [c for c in columns if c not in derived_fields]
    # Always include id in columns
    if columns and "id" not in columns:
        columns.insert(0, "id")

    results = controller.recorder.db.get_by_ids(ids, columns=columns, ordered_headers=True)

    if derived_fields:
        for entry in results:
            headers = entry.get("response", {}).get("headers") or []
            header_dict = {k.lower(): v for k, v in headers}
            content_type = header_dict.get("content-type", "unknown")
            if "content_type" in derived_fields:
                entry["content_type"] = content_type
            if "response_content_type" in derived_fields:
                entry["response_content_type"] = content_type

    if full_body and not columns:
        # Replace truncated previews with full bodies
        for entry in results:
            req = entry.get("request")
            if req:
                flow_obj = controller.recorder.db.get_flow_object(entry["id"])
                if flow_obj and flow_obj.body is not None:
                    req["body"] = flow_obj.body

    return json.dumps(results, indent=2)


def _json_type_name(value: Any) -> str:
    if isinstance(value, bool):
        return "bool"
    if isinstance(value, int) and not isinstance(value, bool):
        return "int"
    if isinstance(value, float):
        return "float"
    if isinstance(value, str):
        return "str"
    if isinstance(value, list):
        return "list"
    if isinstance(value, dict):
        return "dict"
    if value is None:
        return "null"
    return type(value).__name__


@mcp.tool()
async def get_flow_schema(flow_id: str) -> str:
    """Infer a simple schema from a flow's JSON response body."""
    flow_data = controller.recorder.get_flow_detail(flow_id)
    if not flow_data:
        return "Flow not found."

    response = flow_data.get("response")
    body_content = response.get("body_preview") if response else None

    flow_obj = controller.recorder.db.get_flow_object(flow_id)
    response_obj = getattr(flow_obj, "response", None) if flow_obj else None
    full_content = getattr(response_obj, "content", None) if response_obj else None
    if full_content:
        if isinstance(full_content, bytes):
            body_content = full_content.decode("utf-8", errors="replace")
        else:
            body_content = str(full_content)

    if not body_content:
        return "Flow has no response body."

    try:
        data = json.loads(body_content)
    except json.JSONDecodeError:
        return "Response body is not valid JSON."

    if not isinstance(data, dict):
        return f"Response is JSON but not an object (it's {type(data).__name__})."

    schema = {key: _json_type_name(value) for key, value in data.items()}
    return json.dumps(schema, indent=2)


@mcp.tool()
async def load_traffic_file(
    file_path: str,
    append: bool = False,
    scope: str = None,
) -> str:
    """
    Import flows from a HAR or mitmproxy flow file into the traffic database.
    After import, all traffic inspection tools work on the imported data.
    No proxy needs to be running.
    Args:
        file_path: Path to .har or .mitm/.flow file
        append: If True, keep existing traffic. If False (default), clear first.
        scope: Comma-separated list of domains to filter by during import.
            Only flows matching these domains are imported.
    """
    scope_list = [d.strip() for d in scope.split(",") if d.strip()] if scope else None

    # Security: Prevent path traversal and restrict to working directory
    try:
        requested_path = _validate_contained_path(file_path, allow_append_prefix=False)
    except PermissionError as e:
        return json.dumps({
            "status": "error",
            "message": str(e),
        })
    except Exception as e:
        return json.dumps({"status": "error", "message": f"Invalid path: {str(e)}"})

    try:
        stats = await asyncio.to_thread(
            controller.recorder.db.import_from_file,
            str(requested_path),
            append=append,
            scope=scope_list,
        )
        return json.dumps(
            {
                "status": "ok",
                "imported": stats["imported"],
                "skipped": stats["skipped"],
                "errors": stats["errors"],
            }
        )
    except Exception as e:
        return json.dumps({"status": "error", "message": str(e)})


@mcp.tool()
async def extract_from_flow(flow_id: str, json_path: str = None, css_selector: str = None) -> str:
    """
    Extract specific data from a flow's response body using JSONPath or CSS
    selectors.
    Args:
        flow_id: The ID of the captured flow
        json_path: A JSONPath expression to extract data from a JSON response
        css_selector: A CSS selector to extract data from an HTML/XML response
    """
    flow_data = controller.recorder.get_flow_detail(flow_id)
    if not flow_data:
        return "No matching flow."

    response = flow_data.get("response")
    body_content = response.get("body_preview") if response else None
    if not body_content:
        return "Flow has no response body."

    if json_path:
        try:
            # Parse body as JSON
            data = json.loads(body_content)
            # Apply JSONPath
            jsonpath_expr = parse_jsonpath(json_path)
            matches = [match.value for match in jsonpath_expr.find(data)]
            return json.dumps(matches, indent=2)
        except json.JSONDecodeError:
            return "Response body is not valid JSON."
        except Exception as e:
            return f"Error executing JSONPath: {str(e)}"

    if css_selector:
        try:
            soup = BeautifulSoup(body_content, "html.parser")
            elements = soup.select(css_selector)

            result = []
            for el in elements:
                result.append({"text": el.get_text(strip=True), "html": str(el), "attrs": el.attrs})

            return json.dumps(result, indent=2)
        except Exception as e:
            return f"Error executing CSS Selector: {str(e)}"

    return "You must provide a json_path or a css_selector."


@mcp.tool()
async def search_traffic(
    query: str = None,
    domain: str = None,
    method: str = None,
    limit: int = 50,
) -> str:
    """
    Search captured traffic using filters.
    Args:
        query: Keywords to search in URL or body
        domain: Filter by domain name
        method: Filter by HTTP method (GET, POST, etc.)
        limit: Max results to return
    """
    results = controller.recorder.search(query, domain, method, limit)
    return json.dumps(results, indent=2)


@mcp.tool()
async def set_session_variable(name: str, value: str) -> str:
    """Manually set a session variable to use in replayed flows."""
    controller.session_variables[name] = value
    return f"Set session variable ${name} = {value}"


@mcp.tool()
async def extract_session_variable(
    name: str, flow_id: str, regex_pattern: str, group_index: int = 1
) -> str:
    """
    Extract a value from a flow's response body using a regex and store it as a session variable.
    Args:
        name: Variable name (referenced as $name in replay_flow)
        flow_id: The ID of the flow to extract from
        regex_pattern: The regex pattern with capture groups
        group_index: Which regex capture group to extract (default: 1)
    """
    flow_data = controller.recorder.get_flow_detail(flow_id)
    if not flow_data:
        return "No matching flow."

    response = flow_data.get("response")
    body_content = response.get("body_preview") if response else None
    if not body_content:
        return "Flow has no response body."
    try:
        match = re2.search(regex_pattern, body_content)
        if match:
            value = match.group(group_index)
            controller.session_variables[name] = value
            return f"Extracted and set ${name} = {value}"
        else:
            return f"Pattern not found in response body."
    except Exception as e:
        return f"Error applying regex: {str(e)}"


def _resolve_template(template_str: str, variables: dict) -> str:
    """Resolves $variable placeholders in a string."""
    result = template_str
    for k, v in variables.items():
        result = result.replace(f"${k}", str(v))
    return result


@mcp.tool()
async def clear_traffic() -> str:
    """Clear all captured traffic from the database."""
    controller.recorder.clear()
    return "Cleared all traffic history."


@mcp.tool()
async def fuzz_endpoint(
    flow_id: str,
    target_param: str,
    param_type: str,
    payload_category: str,
    timeout: float = 10.0,
) -> str:
    """
    Fuzz an endpoint by substituting a target parameter with a category of
    DAST payloads.
    Args:
        flow_id: The flow to replay as the base request.
        target_param: The name of the parameter to replace.
        param_type: The location of the parameter: 'query' or 'json_body'.
        payload_category: The category of payloads
        ('sqli', 'xss', 'path_traversal').
    """
    flow_data = controller.recorder.get_flow_detail(flow_id)
    if not flow_data:
        return "No matching flow."

    if payload_category == "sqli":
        payloads = [
            "'",
            '"',
            "' OR '1'='1",
            "'; DROP TABLE users--",
            "1' ORDER BY 1--+",
        ]
    elif payload_category == "xss":
        payloads = [
            "<script>alert(1)</script>",
            '"><script>alert(1)</script>',
            "<img src=x onerror=alert(1)>",
        ]
    elif payload_category == "path_traversal":
        payloads = [
            "../../../etc/passwd",
            "..%2F..%2F..%2Fetc%2Fpasswd",
            "/windows/win.ini",
        ]
    else:
        return "Unknown payload category. Use 'sqli', 'xss', or 'path_traversal'."

    original_request = flow_data["request"]
    base_url = original_request["url"]
    method = original_request["method"]

    target_headers = dict(original_request["headers"])
    target_headers.pop("Host", None)
    target_headers.pop("Content-Length", None)
    target_headers.pop("Content-Encoding", None)

    # Get baseline response for anomaly detection
    try:
        baseline_resp = flow_data.get("response") if flow_data else None
        if baseline_resp and baseline_resp.get("status_code") is not None:
            baseline_status = baseline_resp["status_code"]
        else:
            baseline_status = 200

        if baseline_resp and baseline_resp.get("body_preview"):
            baseline_len = len(baseline_resp["body_preview"])
        else:
            baseline_len = 0
    except Exception:
        baseline_status = 200
        baseline_len = 0

    proxy_url = f"http://127.0.0.1:{controller.port}"
    anomalies = []

    async with AsyncSession(
        impersonate="chrome120",
        proxies={"http": proxy_url, "https": proxy_url},
        verify=controller._get_verify_param(),
        timeout=timeout,
    ) as client:
        tasks = []
        for payload in payloads:
            req_url = base_url
            req_body = None

            if param_type == "query":
                parsed_url = urlparse(base_url)
                qs = parse_qsl(parsed_url.query)
                new_qs = [(k, payload if k == target_param else v) for k, v in qs]
                # If param didn't exist, add it
                if target_param not in [k for k, v in qs]:
                    new_qs.append((target_param, payload))

                req_url = parsed_url._replace(query=urlencode(new_qs)).geturl()

                if original_request.get("body_preview"):
                    flow_obj = controller.recorder.db.get_flow_object(flow_id)
                    req_body = flow_obj.body
                    if not req_body:
                        req_body = original_request.get("body_preview")

            elif param_type == "json_body":
                flow_obj = controller.recorder.db.get_flow_object(flow_id)
                body_content = flow_obj.body
                if not body_content:
                    body_content = original_request.get("body_preview", "")

                try:
                    if isinstance(body_content, bytes):
                        body_content = body_content.decode("utf-8")
                    body_data = json.loads(body_content)
                    if target_param in body_data:
                        body_data[target_param] = payload
                    else:
                        # Simple nested replacement naive approach could be added here
                        body_data[target_param] = payload
                    req_body = json.dumps(body_data)
                except Exception as e:
                    return f"Failed to parse or modify JSON body: {str(e)}"
            else:
                return "Unknown param_type. Use 'query' or 'json_body'."

            # Coroutine for the request
            async def run_req(p=payload, u=req_url, b=req_body):
                try:
                    request_kwargs = {
                        "method": method,
                        "url": u,
                        "headers": target_headers,
                    }
                    if b is not None:
                        request_kwargs["data"] = b

                    resp = await client.request(**request_kwargs)

                    status = resp.status_code
                    content_len = len(resp.content) if resp.content else 0

                    # Anomaly detection heuristics
                    if status >= 500:
                        return {
                            "payload": p,
                            "anomaly": "Server Error (5xx)",
                            "status": status,
                        }
                    if status != baseline_status:
                        return {
                            "payload": p,
                            "anomaly": (f"Status Code Deviation ({baseline_status} -> {status})"),
                            "status": status,
                        }

                    # Length deviation by > 20%
                    if baseline_len > 0:
                        diff_ratio = abs(content_len - baseline_len) / baseline_len
                        if diff_ratio > 0.2:
                            return {
                                "payload": p,
                                "anomaly": "Content Length Deviation (>20%)",
                                "status": status,
                                "len": content_len,
                            }
                    return None
                except Exception as e:
                    return {
                        "payload": p,
                        "anomaly": f"Request Failed: {str(e)}",
                    }

            tasks.append(run_req())

        # Run concurrently
        results = await asyncio.gather(*tasks)
        for r in results:
            if r:
                anomalies.append(r)

    if not anomalies:
        return "Fuzzing complete, No significant anomalies detected."

    return json.dumps(
        {
            "baseline_status": baseline_status,
            "baseline_len": baseline_len,
            "anomalies": anomalies,
        },
        indent=2,
    )


@mcp.tool()
async def replay_flow(
    flow_id: str,
    method: str = None,
    headers_json: str = None,
    body: str = None,
    timeout: float = 30.0,
) -> str:
    """
    Replay a captured flow, optionally with modified method, headers, or body.
    Supports session variable injection (e.g., $token) in headers and body.
    """

    # Resolve templates in headers and body if we have variables
    resolved_headers_json = headers_json
    resolved_body = body

    # Treat the sentinel value "__omit__" as no body
    if resolved_body == "__omit__":
        resolved_body = None

    if controller.session_variables:
        if resolved_headers_json:
            resolved_headers_json = _resolve_template(
                resolved_headers_json, controller.session_variables
            )
        if resolved_body:
            resolved_body = _resolve_template(resolved_body, controller.session_variables)

    parsed_headers = None
    if resolved_headers_json:
        try:
            parsed_headers = json.loads(resolved_headers_json)
        except json.JSONDecodeError:
            return "The headers_json parameter needs to be valid JSON."

    return await controller.replay_request(
        flow_id,
        method,
        parsed_headers,
        resolved_body,
        timeout,
    )


@mcp.tool()
async def add_interception_rule(
    rule_id: str,
    action_type: str,
    url_pattern: str = ".*",
    method: str = None,
    key: str = None,
    value: str = None,
    search_pattern: str = None,
    phase: str = "request",
) -> str:
    if phase not in ["request", "response"]:
        return "Phase needs to be either 'request' or 'response'"

    try:
        rule = InterceptionRule(
            id=rule_id,
            url_pattern=url_pattern,
            method=method,
            resource_type=phase,  # type: ignore
            action_type=action_type,  # type: ignore
            key=key,
            value=value,
            search_pattern=search_pattern,
        )
    except Exception as e:
        return f"Invalid rule parameters: {str(e)}"

    if not controller.interceptor.add_rule(rule):
        return f"Invalid or unsupported regex for rule '{rule_id}'"
    return f"Added rule '{rule_id}'"


@mcp.tool()
async def list_rules() -> str:
    rules_dict = {
        rid: {
            "action": r.action_type,
            "url_pattern": r.url_pattern,
            "phase": r.resource_type,
        }
        for rid, r in controller.interceptor.rules.items()
    }
    return json.dumps(rules_dict, indent=2)


@mcp.tool()
async def clear_rules() -> str:
    controller.interceptor.clear_rules()
    return "Cleared all interception rules."


@mcp.tool()
async def list_tools() -> str:
    """List all available tools with their descriptions."""
    tools = await mcp.list_tools()
    tool_list = []
    for tool in tools:
        tool_list.append(
            {"name": tool.name, "description": tool.description, "input_schema": tool.inputSchema}
        )
    return json.dumps(tool_list, indent=2)


# --- API Analysis Tools (Updated for Dicts) ---


def _normalize_path(path: str) -> Tuple[str, List[str]]:
    segments = path.split("/")
    normalized = []
    params = []

    for seg in segments:
        if not seg:
            normalized.append("")
            continue
        if re.match(r"^\d+$", seg):
            normalized.append("{id}")
            params.append("id")
        elif re.match(
            r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-"
            r"[0-9a-f]{12}$",
            seg,
            re.I,
        ):
            normalized.append("{uuid}")
            params.append("uuid")
        elif re.match(r"^[0-9a-f]{24}$", seg, re.I):
            normalized.append("{objectId}")
            params.append("objectId")
        elif len(seg) > 20 and re.match(r"^[a-zA-Z0-9_-]+$", seg):
            normalized.append("{token}")
            params.append("token")
        else:
            normalized.append(seg)

    return "/".join(normalized), params


def _detect_content_type(headers: Dict[str, Any]) -> str:
    ct = headers.get("content-type", headers.get("Content-Type", ""))
    if "json" in ct.lower():
        return "json"
    elif "form" in ct.lower():
        return "form"
    elif "xml" in ct.lower():
        return "xml"
    elif "text" in ct.lower():
        return "text"
    return "unknown"


def _generate_openapi_spec(
    clusters: List[Dict[str, Any]],
    title: str = "Reconstructed API",
    version: str = "1.0.0",
) -> Dict[str, Any]:
    """Reconstructs an OpenAPI v3 spec from API clusters."""
    spec = {
        "openapi": "3.0.0",
        "info": {"title": title, "version": version},
        "paths": {},
    }

    for cluster in clusters:
        path = cluster["path_pattern"]
        # OpenAPI paths must start with /
        if not path.startswith("/"):
            path = "/" + path

        method = cluster["method"].lower()

        if path not in spec["paths"]:
            spec["paths"][path] = {}

        operation = {
            "summary": f"{method.upper()} {path}",
            "parameters": [],
            "responses": {},
        }

        # Add path params
        for param in cluster["path_params"]:
            operation["parameters"].append(
                {
                    "name": param,
                    "in": "path",
                    "required": True,
                    "schema": {"type": "string"},
                }
            )

        # Add query params
        for param in cluster["query_params"]:
            operation["parameters"].append(
                {
                    "name": param,
                    "in": "query",
                    # We could guess type here, default to string
                    "schema": {"type": "string"},
                }
            )

        # Add headers as parameters if significant
        # (simplified, ignoring common browser headers already handled)

        # Responses
        for status_code, count in cluster["status_codes"].items():
            content_types = cluster["content_types"]
            # Default response description
            desc = f"Response with status {status_code}"

            resp_obj = {"description": desc}

            if content_types:
                resp_obj["content"] = {}
                for ct in content_types:
                    if ct == "json":
                        media_type = "application/json"
                    elif ct == "xml":
                        media_type = "application/xml"
                    elif ct == "form":
                        media_type = "application/x-www-form-urlencoded"
                    else:
                        media_type = "text/plain"

                    # Could be populated with inferred schema
                    resp_obj["content"][media_type] = {"schema": {"type": "object"}}

            operation["responses"][str(status_code)] = resp_obj

        spec["paths"][path][method] = operation

    return spec


@mcp.tool()
async def export_openapi_spec(domain: str = None, limit: int = None) -> str:
    """
    Exports captured API traffic patterns to an OpenAPI v3 JSON specification.
    Args:
        domain: Filter traffic by domain
        limit: Max number of traffic flows to analyze. None = all flows.
    """
    patterns_json = await get_api_patterns(domain, limit)
    clusters = json.loads(patterns_json)

    spec = _generate_openapi_spec(
        clusters,
        title=f"Reconstructed API - {domain if domain else 'All'}",
    )
    return json.dumps(spec, indent=2)


@mcp.tool()
async def get_api_patterns(domain: str = None, limit: int = None) -> str:
    """
    Cluster captured traffic into endpoint patterns.
    Args:
        domain: Filter traffic by domain
        limit: Max number of flows to analyze. None = all flows.
    """
    flows = controller.recorder.get_all_for_analysis(lightweight=True)

    if domain:
        flows = [f for f in flows if domain in f["request"]["url"]]

    if limit is not None:
        flows = flows[:limit]

    endpoint_clusters: Dict[str, Dict[str, Any]] = {}

    for f in flows:
        parsed = urlparse(f["request"]["url"])
        normalized_path, path_params = _normalize_path(parsed.path)
        method = f["request"]["method"]
        key = f"{method} {normalized_path}"

        if key not in endpoint_clusters:
            endpoint_clusters[key] = {
                "method": method,
                "path_pattern": normalized_path,
                "path_params": path_params,
                "query_params": set(),
                "request_headers": Counter(),
                "response_status_codes": Counter(),
                "content_types": Counter(),
                "sample_flow_ids": [],
                "count": 0,
            }

        cluster = endpoint_clusters[key]
        cluster["count"] += 1
        cluster["sample_flow_ids"].append(f["id"])

        query_params = parse_qs(parsed.query)
        for param in query_params.keys():
            cluster["query_params"].add(param)

        skip_headers = {
            "host",
            "user-agent",
            "accept",
            "accept-encoding",
            "accept-language",
            "connection",
            "content-length",
            "content-type",
        }
        for h in f["request"]["headers"]:
            if h.lower() not in skip_headers:
                cluster["request_headers"][h] += 1

        if f["response"]:
            ct_key = _detect_content_type(f["response"]["headers"])
            cluster["response_status_codes"][f["response"]["status_code"]] += 1
            cluster["content_types"][ct_key] += 1

    result = []
    for key, cluster in sorted(endpoint_clusters.items(), key=lambda x: -x[1]["count"]):
        result.append(
            {
                "endpoint": key,
                "method": cluster["method"],
                "path_pattern": cluster["path_pattern"],
                "path_params": cluster["path_params"],
                "query_params": list(cluster["query_params"]),
                "common_headers": dict(cluster["request_headers"].most_common(10)),
                "status_codes": dict(cluster["response_status_codes"]),
                "content_types": dict(cluster["content_types"]),
                "request_count": cluster["count"],
                "sample_flow_ids": cluster["sample_flow_ids"][:3],
            }
        )

    return json.dumps(result, indent=2)


@mcp.tool()
async def detect_auth_pattern(flow_ids: str = None) -> str:
    if flow_ids:
        target_ids = [fid.strip() for fid in flow_ids.split(",") if fid.strip()]
        flows = controller.recorder.get_by_ids(target_ids)
    else:
        flows = controller.recorder.get_all_for_analysis()

    auth_signals = {
        "oauth2": {"detected": False, "signals": [], "flows": []},
        "jwt": {"detected": False, "signals": [], "flows": []},
        "api_key": {"detected": False, "signals": [], "flows": []},
        "session_cookie": {"detected": False, "signals": [], "flows": []},
        "csrf": {"detected": False, "signals": [], "flows": []},
        "basic_auth": {"detected": False, "signals": [], "flows": []},
        "bearer_token": {"detected": False, "signals": [], "flows": []},
    }

    for f in flows:
        headers = f["request"]["headers"]
        path = urlparse(f["request"]["url"]).path.lower()

        auth_header = headers.get(
            "Authorization",
            headers.get("authorization", ""),
        )

        if auth_header.startswith("Bearer "):
            token = auth_header[7:]
            auth_signals["bearer_token"]["detected"] = True
            auth_signals["bearer_token"]["flows"].append(f["id"])
            if token.count(".") == 2:
                auth_signals["jwt"]["detected"] = True
                auth_signals["jwt"]["signals"].append("Bearer token appears to be JWT format")
                auth_signals["jwt"]["flows"].append(f["id"])

        if auth_header.startswith("Basic "):
            auth_signals["basic_auth"]["detected"] = True
            auth_signals["basic_auth"]["flows"].append(f["id"])

        for h, v in headers.items():
            h_lower = h.lower()
            if any(k in h_lower for k in ["x-api-key", "api-key", "apikey", "x-auth-token"]):
                auth_signals["api_key"]["detected"] = True
                auth_signals["api_key"]["signals"].append(f"Header: {h}")
                auth_signals["api_key"]["flows"].append(f["id"])

        if any(p in path for p in ["/oauth", "/token", "/authorize", "/auth/callback"]):
            auth_signals["oauth2"]["detected"] = True
            auth_signals["oauth2"]["signals"].append(f"OAuth endpoint: {path}")
            auth_signals["oauth2"]["flows"].append(f["id"])

        body_text = f["request"].get("body")
        if body_text:
            if any(
                p in body_text.lower()
                for p in [
                    "grant_type=",
                    "refresh_token=",
                    "client_id=",
                ]
            ):
                auth_signals["oauth2"]["detected"] = True
                auth_signals["oauth2"]["signals"].append("OAuth2 parameters in request body")
                auth_signals["oauth2"]["flows"].append(f["id"])

        cookie_header = headers.get("Cookie", headers.get("cookie", ""))
        if cookie_header:
            cookies = cookie_header.split(";")
            for cookie in cookies:
                c_name = cookie.strip().split("=")[0].lower() if "=" in cookie else ""
                if any(s in c_name for s in ["session", "sid", "sess", "auth"]):
                    auth_signals["session_cookie"]["detected"] = True
                    auth_signals["session_cookie"]["signals"].append(f"Session cookie: {c_name}")
                    auth_signals["session_cookie"]["flows"].append(f["id"])

        for h, v in headers.items():
            h_lower = h.lower()
            if any(c in h_lower for c in ["csrf", "xsrf", "x-csrf", "x-xsrf"]):
                auth_signals["csrf"]["detected"] = True
                auth_signals["csrf"]["signals"].append(f"CSRF header: {h}")
                auth_signals["csrf"]["flows"].append(f["id"])

    for key in auth_signals:
        auth_signals[key]["flows"] = list(set(auth_signals[key]["flows"]))[:5]
        auth_signals[key]["signals"] = list(set(auth_signals[key]["signals"]))

    detected = [k for k, v in auth_signals.items() if v["detected"]]

    return json.dumps(
        {
            "detected_auth_types": detected,
            "details": auth_signals,
        },
        indent=2,
    )


@mcp.tool()
async def generate_scraper_code(flow_ids: str, target_framework: str = "curl_cffi") -> str:
    """
    Generate executable scraper/automation code from a comma-separated list of
    flow IDs.
    Args:
        flow_ids: Comma-separated list of flow IDs to include in the script.
        target_framework: The framework to generate code for.
    """
    ids = [fid.strip() for fid in flow_ids.split(",") if fid.strip()]
    flows_data = []

    for fid in ids:
        data = controller.recorder.get_flow_detail(fid)
        if data:
            flows_data.append(data)

    if not flows_data:
        return "No valid flows found for the provided IDs."

    normalized_flows = normalize_scraper_flows(flows_data, controller.recorder)
    return render_scraper_code(target_framework, normalized_flows)


def _env_flag(name: str, default: bool = False) -> bool:
    """Parse a boolean env var (1/true/yes/on are truthy, case-insensitive)."""
    val = os.environ.get(name)
    if val is None:
        return default
    return val.strip().lower() in ("1", "true", "yes", "on")


def _parse_port(value: str) -> int:
    try:
        port = int(value)
    except (TypeError, ValueError) as exc:
        raise ValueError("listen port must be an integer between 1 and 65535") from exc
    _validate_listen_port(port)
    return port


def start():
    """Entry point for running the server directly."""
    import argparse

    parser = argparse.ArgumentParser(description="mitmproxy-mcp server")
    parser.add_argument(
        "--dump-file",
        default=os.environ.get("MITMPROXY_DUMP_FILE"),
        help="Path to save raw .flow data. Prefix with + to append. "
        "Can also be set via MITMPROXY_DUMP_FILE env var.",
    )
    parser.add_argument(
        "--upstream-proxy",
        default=os.environ.get("MITMPROXY_UPSTREAM_PROXY"),
        help="Upstream proxy URL (e.g., http://user:pass@proxy:port). "
        "Can also be set via MITMPROXY_UPSTREAM_PROXY env var.",
    )
    parser.add_argument(
        "--port",
        type=_parse_port,
        default=_parse_port(os.environ.get("MITMPROXY_PORT", "8080")),
        help="Default proxy listen port used by start_proxy and --auto-start "
        "(default 8080). Can also be set via MITMPROXY_PORT env var.",
    )
    parser.add_argument(
        "--host",
        default=os.environ.get("MITMPROXY_HOST", "127.0.0.1"),
        help="Default proxy listen host (default 127.0.0.1). "
        "Can also be set via MITMPROXY_HOST env var.",
    )
    parser.add_argument(
        "--auto-start",
        action="store_true",
        default=_env_flag("MITMPROXY_AUTO_START"),
        help="Start the proxy immediately on server startup instead of waiting "
        "for the start_proxy tool. Can also be set via MITMPROXY_AUTO_START env var.",
    )
    parser.add_argument(
        "--allow-remote-bind",
        action="store_true",
        default=_env_flag("MITMPROXY_ALLOW_REMOTE_BIND"),
        help="Allow binding the proxy to a non-loopback host. Can also be set via "
        "MITMPROXY_ALLOW_REMOTE_BIND env var.",
    )
    parser.add_argument(
        "--web",
        action="store_true",
        default=_env_flag("MITMPROXY_WEB"),
        help="Serve the mitmweb UI alongside the proxy by default. Can also be set "
        "via MITMPROXY_WEB env var.",
    )
    parser.add_argument(
        "--web-port",
        type=_parse_port,
        default=_parse_port(os.environ.get("MITMPROXY_WEB_PORT", "8081")),
        help="Default web UI port (default 8081). Can also be set via "
        "MITMPROXY_WEB_PORT env var.",
    )
    parser.add_argument(
        "--web-host",
        default=os.environ.get("MITMPROXY_WEB_HOST", "127.0.0.1"),
        help="Default web UI host (default 127.0.0.1). Can also be set via "
        "MITMPROXY_WEB_HOST env var.",
    )
    parser.add_argument(
        "--web-password",
        default=os.environ.get("MITMPROXY_WEB_PASSWORD") or None,
        help="Static web UI password instead of a random per-start token. A value "
        "starting with $ is read as an argon2 hash. Prefer the "
        "MITMPROXY_WEB_PASSWORD env var: a flag is visible in the process list.",
    )
    args, _ = parser.parse_known_args()

    global controller
    controller = MitmController(dump_file=args.dump_file)
    controller.cli_upstream_proxy = args.upstream_proxy
    # start_proxy() and --auto-start fall back to these when no port is passed,
    # so a wrapper can pin a per-agent port that the browser also targets.
    controller.default_port = args.port
    controller.default_host = args.host
    controller.default_web = args.web
    controller.default_web_port = args.web_port
    controller.default_web_host = args.web_host
    controller.web_password = args.web_password
    controller.auto_start = args.auto_start
    controller.allow_remote_bind = args.allow_remote_bind

    mcp.run()


if __name__ == "__main__":
    start()
