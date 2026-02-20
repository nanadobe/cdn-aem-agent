"""Privacy helpers to prevent sensitive data disclosure in reports."""

from __future__ import annotations

import re
from typing import Any

_IPV4_CIDR_RE = re.compile(
    r"\b(?:\d{1,3}\.){3}\d{1,3}(?:/\d{1,2})?\b",
    flags=re.IGNORECASE,
)
_IPV6_RE = re.compile(r"\b(?:[A-F0-9]{1,4}:){2,}[A-F0-9:]{1,4}\b", flags=re.IGNORECASE)
_SECRET_ASSIGNMENT_RE = re.compile(
    r"(?i)\b(secret|token|password|passwd|apikey|api_key|client_secret)\b"
    r"\s*[:=]\s*([^\s,;]+)"
)
_BEARER_RE = re.compile(r"(?i)\bbearer\s+[a-z0-9\-\._~\+/]+=*")
_LONG_TOKEN_RE = re.compile(r"\b(?=[A-Za-z0-9]{24,}\b)(?=.*[A-Za-z])(?=.*\d)[A-Za-z0-9]{24,}\b")


def redact_text(value: str) -> str:
    """Redact common sensitive literals while preserving readability."""
    text = _IPV4_CIDR_RE.sub("<redacted-ip>", value)
    text = _IPV6_RE.sub("<redacted-ipv6>", text)
    text = _SECRET_ASSIGNMENT_RE.sub(r"\1=<redacted-secret>", text)
    text = _BEARER_RE.sub("Bearer <redacted-token>", text)
    text = _LONG_TOKEN_RE.sub(_maybe_redact_long_token, text)
    return text


def redact_requirement_text(value: str) -> str:
    """Sanitize requirement text before persisting in metadata."""
    return redact_text(value)


def maybe_redact_value(value: Any) -> Any:
    """Redact string values, passthrough non-strings."""
    if isinstance(value, str):
        return redact_text(value)
    return value


def redact_structure(value: Any) -> Any:
    """Recursively redact nested structures for safe reporting."""
    if isinstance(value, dict):
        return {str(key): redact_structure(item) for key, item in value.items()}
    if isinstance(value, list):
        return [redact_structure(item) for item in value]
    if isinstance(value, str):
        return redact_text(value)
    return value


def _maybe_redact_long_token(match: re.Match[str]) -> str:
    token = match.group(0)
    # Preserve readable rule names and stable identifiers.
    if token.isalpha():
        return token
    if "-" in token and token.lower().startswith(("block", "allow", "rate")):
        return token
    return "<redacted-value>"
