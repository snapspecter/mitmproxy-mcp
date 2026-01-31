from typing import Dict, List, Optional, Literal
from pydantic import BaseModel, Field


class InterceptionRule(BaseModel):
    """Defines a rule for modifying traffic."""

    id: str
    active: bool = True
    # Triggers
    url_pattern: Optional[str] = None
    method: Optional[str] = None
    resource_type: Literal["request", "response"] = "request"

    # Actions
    action_type: Literal[
        "inject_header",
        "replace_body",
        "block",
    ] = "inject_header"
    key: Optional[str] = None
    value: Optional[str] = None
    search_pattern: Optional[str] = None

    model_config = {"extra": "ignore"}


class ScopeConfig(BaseModel):
    """Rules for what traffic to record/ignore."""

    allowed_domains: List[str] = Field(default_factory=list)
    ignore_extensions: List[str] = Field(
        default_factory=lambda: [
            ".jpg",
            ".jpeg",
            ".png",
            ".gif",
            ".css",
            ".woff",
            ".ico",
            ".svg",
            ".webp",
            ".mp4",
            ".mp3",
            ".ts",
            ".m3u8",
            ".pdf",
            ".woff2",
        ]
    )
    ignore_methods: List[str] = Field(default_factory=lambda: ["OPTIONS"])


class RequestData(BaseModel):
    method: str
    url: str
    headers: Dict[str, str]
    body_preview: Optional[str] = None
    timestamp: float = 0.0


class ResponseData(BaseModel):
    status_code: int
    headers: Dict[str, str]
    body_preview: Optional[str] = None
    size: int = 0


class FlowData(BaseModel):
    id: str
    request: RequestData
    response: Optional[ResponseData] = None
    curl_command: Optional[str] = None
