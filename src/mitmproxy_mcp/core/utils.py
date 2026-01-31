from typing import Optional
from mitmproxy import http


def get_safe_text(message: http.Message) -> Optional[str]:
    """
    Uses Mitmproxy's internal engine to decode traffic.
    Handles Gzip, Brotli, Deflate, and Charsets automatically.
    Returns None if the content is binary/undecodable.
    """
    if not message.content:
        return None
    # strict=False tries headers then UTF-8 then returns None on failure
    return message.get_text(strict=False)
