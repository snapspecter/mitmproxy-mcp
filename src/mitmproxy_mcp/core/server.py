import asyncio
import logging
import sys
import json
from collections import Counter
from typing import List, Dict, Any, Optional, Tuple
from urllib.parse import urlparse, parse_qs, urlencode, parse_qsl
import re

import structlog

from mcp.server.fastmcp import FastMCP
from mitmproxy import options
from mitmproxy.tools.dump import DumpMaster
from curl_cffi.requests import AsyncSession
from jsonpath_ng import parse as parse_jsonpath
from bs4 import BeautifulSoup

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
        self.session_variables = {}

    async def start(self, port: int = 8080, host: str = "0.0.0.0"):
        if self.running:
            return "MITM is already running."

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
                req_data = None
                req_content = None
                if isinstance(target_content, str):
                    req_data = target_content
                elif isinstance(target_content, bytes):
                    req_content = target_content

                response = await client.request(
                    method=target_method,
                    url=target_url,
                    headers=target_headers,
                    data=req_data,
                    content=req_content,
                )

            return (
                f"Replayed successfully! (Status: {response.status_code}). Check the traffic summary for the new flow."
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
async def inspect_flow(flow_id: str) -> str:
    logger.debug("inspect_flow", flow_id=flow_id)
    data = controller.recorder.get_flow_detail(flow_id)
    if not data:
        return "Couldn't find that flow."
    return json.dumps(data, indent=2)


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
    if not response or not response.get("body"):
        return "Flow has no response body."

    body_content = response["body"]

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
async def extract_session_variable(name: str, flow_id: str, regex_pattern: str, group_index: int = 1) -> str:
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
    if not response or not response.get("body"):
        return "Flow has no response body."
    try:
        match = re.search(regex_pattern, response["body"])
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
        baseline_flow = controller.recorder.db.get_flow_object(flow_id)
        if baseline_flow and baseline_flow.response:
            baseline_status = baseline_flow.response.status_code
        else:
            baseline_status = 200

        if baseline_flow and baseline_flow.response and baseline_flow.response.content:
            baseline_len = len(baseline_flow.response.content)
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
        verify=False,
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
                    resp = await client.request(
                        method=method,
                        url=u,
                        headers=target_headers,
                        data=b if isinstance(b, str) else None,
                        content=b if isinstance(b, bytes) else None,
                    )

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

    if controller.session_variables:
        if resolved_headers_json:
            resolved_headers_json = _resolve_template(resolved_headers_json, controller.session_variables)
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


@mcp.tool()
async def list_tools() -> str:
    """List all available tools with their descriptions."""
    tools = await mcp.list_tools()
    tool_list = []
    for tool in tools:
        tool_list.append({"name": tool.name, "description": tool.description, "input_schema": tool.inputSchema})
    return json.dumps(tool_list, indent=2)


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
            operation["parameters"].append({
                "name": param,
                "in": "path",
                "required": True,
                "schema": {"type": "string"},
            })

        # Add query params
        for param in cluster["query_params"]:
            operation["parameters"].append({
                "name": param,
                "in": "query",
                # We could guess type here, default to string
                "schema": {"type": "string"},
            })

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
async def export_openapi_spec(domain: str = None, limit: int = 50) -> str:
    """
    Exports captured API traffic patterns to an OpenAPI v3 JSON specification.
    Args:
        domain: Filter traffic by domain
        limit: Max number of traffic flows to analyze
    """
    patterns_json = await get_api_patterns(domain, limit)
    clusters = json.loads(patterns_json)

    spec = _generate_openapi_spec(
        clusters,
        title=f"Reconstructed API - {domain if domain else 'All'}",
    )
    return json.dumps(spec, indent=2)


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
        result.append({
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
        })

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


@mcp.tool()
async def generate_scraper_code(flow_ids: str, target_framework: str = "curl_cffi") -> str:
    """
    Generate executable scraper/automation code from a comma-separated list of
    flow IDs.
    Args:
        flow_ids: Comma-separated list of flow IDs to include in the script.
        target_framework: The framework to generate code for (TODO: Add
        additional frameworks: Only 'curl_cffi' is currently supported).
    """
    ids = [fid.strip() for fid in flow_ids.split(",") if fid.strip()]
    flows_data = []

    for fid in ids:
        data = controller.recorder.get_flow_detail(fid)
        if data:
            flows_data.append(data)

    if not flows_data:
        return "No valid flows found for the provided IDs."

    if target_framework == "curl_cffi":
        code = [
            "import asyncio",
            "import json",
            "from curl_cffi.requests import AsyncSession",
            "",
            "async def run_scraper():",
            "    # Generated by mitmproxy-mcp",
            "    async with AsyncSession(",
            "        impersonate='chrome120', verify=False",
            "    ) as client:",
        ]

        for i, flow in enumerate(flows_data):
            req = flow["request"]
            url = req["url"]
            method = req["method"]

            headers = dict(req["headers"])
            headers.pop("Host", None)
            headers.pop("Content-Length", None)
            headers.pop("Content-Encoding", None)

            # Prefer richer in-memory flow object when available,
            # then DB fallback.
            body = req.get("body_preview")

            live_flow = controller.recorder.get_live_flow(flow["id"])
            if live_flow and live_flow.request and live_flow.request.content:
                try:
                    body = live_flow.request.content.decode("utf-8")
                except UnicodeDecodeError:
                    body = body or "<binary data omitted>"
            else:
                flow_obj = controller.recorder.db.get_flow_object(flow["id"])
                if flow_obj and flow_obj.body:
                    body = flow_obj.body

            safe_method = json.dumps(method)
            safe_url = json.dumps(url)
            safe_url_preview = json.dumps(url[:50])
            step_line = f"        print(f'\\n[Step {i + 1}] Executing ' + {safe_method} + ' ' + {safe_url_preview} + '...')"
            code.append(step_line)

            headers_str = json.dumps(headers, indent=12).strip()
            # Indent subsequent lines
            headers_str = headers_str.replace("\n", "\n        ")

            code.append(f"        headers_{i} = {headers_str}")

            kwargs = f"method={safe_method}, url={safe_url}, headers=headers_{i}"

            if body and body != "<binary data omitted>":
                # Escape quotes
                safe_body = json.dumps(body)
                code.append(f"        data_{i} = {safe_body}")
                kwargs += f", data=data_{i}"

            code.append(f"        response_{i} = await client.request({kwargs})")
            code.append(f"        print(f'Status: {{response_{i}.status_code}}')")
            code.append(f"        # print(response_{i}.text[:200])")
            code.append("")

        code.extend([
            "if __name__ == '__main__':",
            "    asyncio.run(run_scraper())",
        ])

        return "\n".join(code)
    else:
        return f"Framework '{target_framework}' is not supported yet."


def start():
    """Entry point for running the server directly."""
    mcp.run()


if __name__ == "__main__":
    start()
