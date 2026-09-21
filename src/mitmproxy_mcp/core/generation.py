import json
from pathlib import Path
from typing import Any, Dict, List

from jinja2 import Environment, FileSystemLoader, PackageLoader, TemplateNotFound

from .untrusted import neutralise_markers

# Headers that carry live credentials. They are replaced with a placeholder
# before any code is generated, so captured secrets never reach the model or
# the generated file.
SENSITIVE_HEADERS = {
    "authorization",
    "proxy-authorization",
    "cookie",
    "set-cookie",
    "x-api-key",
    "x-auth-token",
}

SUPPORTED_FRAMEWORKS = {"curl_cffi", "requests", "aiohttp", "playwright"}

REDACTED = "<REDACTED>"


def _try_load_template_environment() -> Environment:
    package_loader = None
    try:
        package_loader = PackageLoader("mitmproxy_mcp", "templates")
    except (ValueError, ImportError):
        # Package templates unavailable (e.g. running from a source checkout);
        # fall back to the filesystem loader below.
        package_loader = None

    if package_loader is not None:
        # Templates emit Python source, not HTML. Autoescape would HTML-escape
        # quotes and corrupt the generated code.
        env = Environment(  # nosec B701
            loader=package_loader,
            trim_blocks=True,
            lstrip_blocks=True,
        )
    else:
        templates_path = Path(__file__).resolve().parent.parent / "templates"
        # See above: generated artefact is code, not markup.
        env = Environment(  # nosec B701
            loader=FileSystemLoader(str(templates_path)),
            trim_blocks=True,
            lstrip_blocks=True,
        )

    env.globals["to_json"] = lambda value, indent=None: json.dumps(value, indent=indent, ensure_ascii=False)
    return env


def _get_best_request_body(flow: Dict[str, Any], recorder: Any) -> str | None:
    request = flow["request"]
    body = request.get("body_preview")

    live_flow = recorder.get_live_flow(flow["id"])
    if live_flow and getattr(live_flow, "request", None) is not None:
        live_content = getattr(live_flow.request, "content", None)
        if live_content is not None:
            if isinstance(live_content, bytes):
                try:
                    return live_content.decode("utf-8")
                except UnicodeDecodeError:
                    return None
            return str(live_content)

    flow_obj = recorder.db.get_flow_object(flow["id"])
    if flow_obj is not None and getattr(flow_obj, "body", None) is not None:
        stored_body = flow_obj.body
        if isinstance(stored_body, bytes):
            try:
                return stored_body.decode("utf-8")
            except UnicodeDecodeError:
                return None
        return str(stored_body)

    if body is None or body == "":
        return None
    return body


def normalize_scraper_flows(flows: List[Dict[str, Any]], recorder: Any) -> List[Dict[str, Any]]:
    normalized_flows: List[Dict[str, Any]] = []

    for flow in flows:
        request = flow["request"]
        headers = dict(request.get("headers") or {})
        headers.pop("Host", None)
        headers.pop("Content-Length", None)
        headers.pop("Content-Encoding", None)
        for name in list(headers):
            if name.lower() in SENSITIVE_HEADERS:
                headers[name] = REDACTED
            else:
                # Captured values must not be able to forge the untrusted fence
                # that wraps the generated code.
                headers[name] = neutralise_markers(str(headers[name]))

        body = _get_best_request_body(flow, recorder)
        if body is not None:
            body = neutralise_markers(body)

        accept_header = headers.get("Accept") or headers.get("accept") or ""
        is_navigation = request.get("method", "").upper() == "GET" and "text/html" in str(accept_header)

        method = neutralise_markers(str(request.get("method", "GET")))
        url = neutralise_markers(str(request.get("url", "")))
        normalized_flows.append({
            "id": flow["id"],
            "url": url,
            "method": method,
            "headers": headers,
            "body": body,
            "has_body": bool(body),
            "is_navigation": is_navigation,
            "url_preview": url[:50],
        })

    return normalized_flows


def render_scraper_code(target_framework: str, flows: List[Dict[str, Any]]) -> str:
    if target_framework not in SUPPORTED_FRAMEWORKS:
        return f"Framework '{target_framework}' is not supported yet."
    env = _try_load_template_environment()
    try:
        template = env.get_template(f"{target_framework}.jinja2")
    except TemplateNotFound:
        return f"Framework '{target_framework}' is not supported yet."

    return template.render(flows=flows)
