"""Outbound destination policy.

Single enforcement point for every request this server originates on the
agent's behalf (replay and fuzzing). Default-deny: a destination is only
reachable when it matches the operator's configured scope.
"""

import ipaddress
import socket
from typing import List, Optional
from urllib.parse import urlparse

# Ranges that must never be reached by an agent-driven replay unless the
# operator explicitly allowlists the literal host.
_BLOCKED_NETS = [
    ipaddress.ip_network(n)
    for n in (
        "0.0.0.0/8",
        "10.0.0.0/8",
        "100.64.0.0/10",
        "127.0.0.0/8",
        "169.254.0.0/16",
        "172.16.0.0/12",
        "192.168.0.0/16",
        "::1/128",
        "fc00::/7",
        "fe80::/10",
    )
]


def _is_blocked_ip(ip: str) -> bool:
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return True
    # An IPv4-mapped IPv6 address (::ffff:127.0.0.1) must be unwrapped, or it
    # slips past the IPv4 ranges below.
    if isinstance(addr, ipaddress.IPv6Address) and addr.ipv4_mapped:
        addr = addr.ipv4_mapped
    if (
        addr.is_private
        or addr.is_loopback
        or addr.is_link_local
        or addr.is_reserved
        or addr.is_multicast
        or addr.is_unspecified
    ):
        return True
    return any(addr in net for net in _BLOCKED_NETS)


def host_matches_scope(host: str, scope: List[str]) -> bool:
    """Exact or subdomain-suffix match (never a bare substring match)."""
    host = (host or "").lower().rstrip(".")
    if not scope:
        return False
    return any(host == d.lower().rstrip(".") or host.endswith("." + d.lower().rstrip(".")) for d in scope)


def check_destination(url: str, scope: List[str]) -> Optional[str]:
    """Return a denial reason, or None when the destination is permitted.

    Enforced immediately before the outbound call. Hostnames are resolved and
    every resulting address is checked, so a name cannot resolve to a private
    address (DNS rebinding / SSRF) unless it is explicitly in scope.
    """
    parsed = urlparse(url)
    if parsed.scheme not in ("http", "https"):
        return f"destination scheme '{parsed.scheme or '(none)'}' is not allowed"
    host = parsed.hostname
    if not host:
        return "destination has no host"
    if "@" in (parsed.netloc or ""):
        return "destination contains userinfo"

    if scope:
        if not host_matches_scope(host, scope):
            return f"host '{host}' is outside the configured scope"
        return None

    # No scope configured: only public hosts are reachable.
    try:
        infos = socket.getaddrinfo(host, None)
    except OSError:
        return f"host '{host}' could not be resolved"
    for info in infos:
        ip = info[4][0]
        if _is_blocked_ip(ip):
            return f"host '{host}' resolves to a blocked address ({ip})"
    return None
