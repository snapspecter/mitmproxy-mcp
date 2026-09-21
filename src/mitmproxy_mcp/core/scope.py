from mitmproxy import http
from typing import List
from ..models import ScopeConfig


def host_in_scope(host: str, allowed_domains: List[str]) -> bool:
    """Exact host or true subdomain match.

    Never a substring match: an allowlist entry of ``example.com`` must not
    match ``example.com.attacker.net``.
    """
    host = (host or "").lower().rstrip(".")
    if not host:
        return False
    return any(
        host == d.lower().rstrip(".") or host.endswith("." + d.lower().rstrip("."))
        for d in allowed_domains
    )


class ScopeManager:
    """Filters traffic to prevent noise in the LLM context window."""

    def __init__(self, config: ScopeConfig):
        self.config = config

    def is_allowed(self, flow: http.HTTPFlow) -> bool:
        if self.config.allowed_domains:
            if not host_in_scope(flow.request.host, self.config.allowed_domains):
                return False

        path = flow.request.path.lower().split("?")[0]
        if any(path.endswith(ext) for ext in self.config.ignore_extensions):
            return False

        if flow.request.method in self.config.ignore_methods:
            return False

        return True

    def update_domains(self, domains: List[str]):
        self.config.allowed_domains = domains
