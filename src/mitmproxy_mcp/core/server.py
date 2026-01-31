import asyncio
import logging
import sys
import json
from collections import Counter
from typing import List, Dict, Any, Optional, Tuple
from urllib.parse import urlparse, parse_qs

import structlog

from mcp.server.fastmcp import FastMCP
from mitmproxy import options
from mitmproxy.tools.dump import DumpMaster
from curl_cffi.requests import AsyncSession

from ..models import ScopeConfig, InterceptionRule
from .scope import ScopeManager
from .recorder import TrafficRecorder
from .interceptor import TrafficInterceptor

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


class MitmController:
    def __init__(self):
        self.master: Optional[DumpMaster] = None
        self.proxy_task: Optional[asyncio.Task] = None
        self.scope_config = ScopeConfig()
        self.scope_manager = ScopeManager(self.scope_config)
        self.recorder = TrafficRecorder(self.scope_manager)
        self.interceptor = TrafficInterceptor()
        self.running = False
        self.port = 8080

    async def start(self, port: int = 8080, host: str = "0.0.0.0"):
        if self.running:
            return "The proxy's already running!"

        self.port = port
        opts = options.Options(listen_host=host, listen_port=port)
        self.master = DumpMaster(
            opts,
            with_termlog=False,
            with_dumper=False,
        )
        self.master.addons.add(self.recorder)
        self.master.addons.add(self.interceptor)

        self.proxy_task = asyncio.create_task(self.master.run())
        self.running = True
        logger.info("proxy_started", host=host, port=port)
        return f"Started proxy on port {port}"

    async def stop(self):
        if not self.running or not self.master:
            return "The proxy isn't running right now."
        self.master.shutdown()
        if self.proxy_task:
            try:
                await self.proxy_task
            except asyncio.CancelledError:
                pass
            self.proxy_task = None
        self.running = False
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
                verify=False,
                timeout=timeout,
            ) as client:
                response = await client.request(
                    method=target_method,
                    url=target_url,
                    headers=target_headers,
                    data=(target_content if isinstance(target_content, str) else None),
                    content=(target_content if isinstance(target_content, bytes) else None),
                )

            return (
                "Replayed successfully! "
                f"(Status: {response.status_code}). "
                "Check the traffic summary for the new flow."
            )
        except Exception as e:
            logger.error(f"Replay failed: {e}")
            return f"That didn't work: {str(e)}"


# Global Controller Instance
controller = MitmController()

mcp = FastMCP("Mitmproxy Manager")

# --- MCP Tools ---


@mcp.tool()
async def start_proxy(port: int = 8080) -> str:
    try:
        return await controller.start(port=port)
    except Exception as e:
        logger.error("proxy_start_failed", error=str(e))
        return f"Couldn't start the proxy: {str(e)}"


@mcp.tool()
async def stop_proxy() -> str:
    return await controller.stop()


@mcp.tool()
async def set_scope(allowed_domains: List[str]) -> str:
    controller.scope_manager.update_domains(allowed_domains)
    domains_str = ", ".join(allowed_domains) if allowed_domains else "everything"
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
async def inspect_flow(flow_id: str) -> str:
    logger.debug("inspect_flow", flow_id=flow_id)
    data = controller.recorder.get_flow_detail(flow_id)
    if not data:
        return "Couldn't find that flow."
    return json.dumps(data, indent=2)


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
async def clear_traffic() -> str:
    """Clear all captured traffic from the database."""
    controller.recorder.clear()
    return "Cleared all traffic history."


@mcp.tool()
async def replay_flow(
    flow_id: str,
    method: str = None,
    headers_json: str = None,
    body: str = None,
    timeout: float = 30.0,
) -> str:
    parsed_headers = None
    if headers_json:
        try:
            parsed_headers = json.loads(headers_json)
        except json.JSONDecodeError:
            return "The headers_json parameter needs to be valid JSON."

    return await controller.replay_request(
        flow_id,
        method,
        parsed_headers,
        body,
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

    controller.interceptor.add_rule(rule)
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


# --- API Analysis Tools (Updated for Dicts) ---


def _normalize_path(path: str) -> Tuple[str, List[str]]:
    import re

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


def _detect_content_type(headers: Dict[str, str]) -> str:
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


@mcp.tool()
async def get_api_patterns(domain: str = None, limit: int = 50) -> str:
    # Fetch flows from DB
    flows = controller.recorder.get_all_for_analysis(limit * 5)  # Fetch more to filter locally

    if domain:
        flows = [f for f in flows if domain in f["request"]["url"]]

    flows = flows[:limit]  # Re-limit

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
        # This is inefficient, fetching all then filtering.
        # Ideally get_all_for_analysis filters.
        # But for now it's okay.
        flows = controller.recorder.get_all_for_analysis()
        target_ids = set(flow_ids.split(","))
        flows = [f for f in flows if f["id"] in target_ids]
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


def start():
    """Entry point for running the server directly."""
    mcp.run()


if __name__ == "__main__":
    start()
