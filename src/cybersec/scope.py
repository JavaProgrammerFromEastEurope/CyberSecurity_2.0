"""Target URL validation and authorization acknowledgement."""
from __future__ import annotations

from urllib.parse import urlsplit, urlunsplit


class ScopeError(ValueError):
    """Raised when a target URL is invalid or outside supported scope."""


def normalize_target_url(value: str) -> tuple[str, str]:
    """Validate and normalize a web target URL; return (url, hostname)."""
    raw = value.strip()
    if not raw:
        raise ScopeError("Target URL cannot be empty.")

    try:
        parts = urlsplit(raw)
        hostname = parts.hostname
        port = parts.port  # Access can raise ValueError for malformed ports.
    except ValueError as exc:
        raise ScopeError(f"Invalid target URL: {exc}") from exc

    if parts.scheme.lower() not in {"http", "https"}:
        raise ScopeError("Only http:// and https:// target URLs are supported.")
    if not hostname:
        raise ScopeError("Target URL must include a hostname, e.g. https://example.com.")
    if parts.username is not None or parts.password is not None:
        raise ScopeError("Do not embed credentials in target URLs.")
    if any(ch.isspace() for ch in hostname):
        raise ScopeError("Target hostname contains whitespace.")

    scheme = parts.scheme.lower()
    host = hostname.lower()
    if ":" in host and not host.startswith("["):
        host = f"[{host}]"
    netloc = host
    if port is not None:
        netloc = f"{netloc}:{port}"

    path = parts.path or "/"
    normalized = urlunsplit((scheme, netloc, path, parts.query, ""))
    return normalized, hostname.lower()
