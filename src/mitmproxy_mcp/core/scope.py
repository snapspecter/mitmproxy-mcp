from mitmproxy import http
from typing import List
from urllib.parse import urlparse
from ..models import ScopeConfig


class ScopeManager:
    """Filters traffic to prevent noise in the LLM context window."""

    def __init__(self, config: ScopeConfig):
        self.config = config

    @staticmethod
    def _normalize_domain(domain: str) -> str:
        value = domain.strip().lower().rstrip(".")
        if "://" in value:
            value = urlparse(value).hostname or ""
        else:
            value = value.split("/", 1)[0]
            if value.count(":") == 1:
                value = value.split(":", 1)[0]
        value = value.lstrip(".").rstrip(".")
        if not value or any(char.isspace() for char in value):
            raise ValueError(f"Invalid scope domain: {domain!r}")
        return value.encode("idna").decode("ascii")

    def has_scope(self) -> bool:
        return bool(self.config.allowed_domains)

    def is_host_allowed(self, host: str) -> bool:
        if not self.has_scope():
            return False
        normalized_host = self._normalize_domain(host)
        return any(
            normalized_host == domain or normalized_host.endswith("." + domain)
            for domain in self.config.allowed_domains
        )

    def is_allowed(self, flow: http.HTTPFlow) -> bool:
        if not self.is_host_allowed(flow.request.host):
            return False

        path = flow.request.path.lower().split("?")[0]
        if any(path.endswith(ext) for ext in self.config.ignore_extensions):
            return False

        if flow.request.method in self.config.ignore_methods:
            return False

        return True

    def update_domains(self, domains: List[str]):
        self.config.allowed_domains = list(
            dict.fromkeys(self._normalize_domain(domain) for domain in domains)
        )
