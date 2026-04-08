import json
from pathlib import Path
from typing import Any, Dict, List

from jinja2 import Environment, FileSystemLoader, PackageLoader, TemplateNotFound


def _try_load_template_environment() -> Environment:
    package_loader = None
    try:
        package_loader = PackageLoader("mitmproxy_mcp", "templates")
    except Exception:
        pass

    if package_loader is not None:
        env = Environment(
            loader=package_loader,
            trim_blocks=True,
            lstrip_blocks=True,
        )
    else:
        templates_path = Path(__file__).resolve().parent.parent / "templates"
        env = Environment(
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

        body = _get_best_request_body(flow, recorder)

        accept_header = headers.get("Accept") or headers.get("accept") or ""
        is_navigation = request.get("method", "").upper() == "GET" and "text/html" in str(accept_header)

        normalized_flows.append({
            "id": flow["id"],
            "url": request.get("url", ""),
            "method": request.get("method", "GET"),
            "headers": headers,
            "body": body,
            "has_body": bool(body),
            "is_navigation": is_navigation,
            "url_preview": str(request.get("url", ""))[:50],
        })

    return normalized_flows


def render_scraper_code(target_framework: str, flows: List[Dict[str, Any]]) -> str:
    env = _try_load_template_environment()
    try:
        template = env.get_template(f"{target_framework}.jinja2")
    except TemplateNotFound:
        return f"Framework '{target_framework}' is not supported yet."

    return template.render(flows=flows)
