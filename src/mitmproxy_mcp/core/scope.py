from mitmproxy import http
from typing import List
from ..models import ScopeConfig


class ScopeManager:
    """Filters traffic to prevent noise in the LLM context window."""

    def __init__(self, config: ScopeConfig):
        self.config = config

    def is_allowed(self, flow: http.HTTPFlow) -> bool:
        if self.config.allowed_domains:
            host = flow.request.host
            if not any(d in host for d in self.config.allowed_domains):
                return False

        path = flow.request.path.lower().split("?")[0]
        if any(path.endswith(ext) for ext in self.config.ignore_extensions):
            return False

        if flow.request.method in self.config.ignore_methods:
            return False

        return True

    def update_domains(self, domains: List[str]):
        self.config.allowed_domains = domains
