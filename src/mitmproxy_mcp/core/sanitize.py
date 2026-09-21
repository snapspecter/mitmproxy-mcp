"""Input sanitisation for values that end up on the wire or in generated code."""

import re

_CRLF = ("\r", "\n", "\x00")

# RFC 7230 token: field-name
_TOKEN_RE = re.compile(r"^[!#$%&'*+\-.^_`|~0-9A-Za-z]+$")

# Field-value: visible ASCII + SP/HTAB (no CR/LF/NUL).
_FIELD_VALUE_RE = re.compile(r"^[\t\x20-\x7e\x80-\xff]*$")


def is_safe_header_name(name: str) -> bool:
    return isinstance(name, str) and bool(name) and bool(_TOKEN_RE.match(name))


def is_safe_header_value(value: str) -> bool:
    return isinstance(value, str) and "\r" not in value and "\n" not in value and "\x00" not in value


def strip_crlf(value: str) -> str:
    """Remove CR/LF/NUL from a value before it is placed on the wire."""
    if not isinstance(value, str):
        return value
    for ch in _CRLF:
        value = value.replace(ch, "")
    return value


def validate_header(name: str, value: str) -> str | None:
    """Return an error message when a header pair is unsafe, else None."""
    if not is_safe_header_name(name):
        return f"invalid header name: {name!r}"
    if not is_safe_header_value(value):
        return f"header value for {name!r} contains CR/LF/NUL"
    return None
