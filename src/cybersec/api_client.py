"""Small, dependency-free client for the loopback CyberSec HTTP API.

Only GET requests are retried. Mutating requests are never replayed automatically,
so a timeout after POST cannot silently create duplicate targets or jobs.
"""
from __future__ import annotations

import json
import math
import os
import socket
import time
from dataclasses import dataclass
from ipaddress import ip_address
from typing import Any
from urllib.error import HTTPError, URLError
from urllib.parse import urlencode, urlsplit, urlunsplit
from urllib.request import Request, urlopen


@dataclass(frozen=True)
class Page:
    items: list[dict[str, Any]]
    total: int
    limit: int
    offset: int


class APIClientError(RuntimeError):
    """Base exception for client failures."""


class APIConnectionError(APIClientError):
    """The API could not be reached after the allowed attempts."""


class APITimeoutError(APIConnectionError):
    """The API request timed out."""


class APIResponseError(APIClientError):
    """The API returned a non-success HTTP response."""

    def __init__(self, status: int, payload: dict[str, Any] | None = None):
        self.status = status
        self.payload = payload or {}
        self.code = str(self.payload.get("code", "http_error"))
        self.request_id = self.payload.get("request_id")
        message = str(self.payload.get("error", f"API returned HTTP {status}"))
        super().__init__(f"HTTP {status} [{self.code}]: {message}")


class APIProtocolError(APIClientError):
    """The API response was not valid JSON in the expected shape."""


class CyberSecAPIClient:
    """Client for a loopback-only Cyber Security Orchestrator API.

    Args:
        base_url: API origin, for example ``http://127.0.0.1:8765``.
        token: bearer token configured by the API process.
        timeout: per-attempt socket timeout in seconds.
        retries: additional attempts for retryable GET failures only.
        retry_backoff: base delay in seconds, exponentially multiplied per retry.
    """

    RETRYABLE_STATUS = {429, 500, 502, 503, 504}

    def __init__(
        self,
        base_url: str = "http://127.0.0.1:8765",
        *,
        token: str,
        timeout: float = 3.0,
        retries: int = 2,
        retry_backoff: float = 0.15,
    ) -> None:
        if not token or not token.strip():
            raise ValueError("token must not be empty")
        if not math.isfinite(timeout) or timeout <= 0:
            raise ValueError("timeout must be a finite number greater than zero")
        if not 0 <= retries <= 5:
            raise ValueError("retries must be between 0 and 5")
        if not math.isfinite(retry_backoff) or retry_backoff < 0:
            raise ValueError("retry_backoff must be finite and not negative")
        parsed = urlsplit(base_url.rstrip("/"))
        if parsed.scheme != "http" or not parsed.hostname:
            raise ValueError("base_url must be an HTTP loopback origin")
        if parsed.username or parsed.password or parsed.query or parsed.fragment:
            raise ValueError("base_url must not contain credentials, query, or fragment")
        host = parsed.hostname.casefold()
        try:
            is_loopback = ip_address(host).is_loopback
        except ValueError:
            is_loopback = host == "localhost"
        if not is_loopback:
            raise ValueError("API client only permits loopback hosts")
        if parsed.path not in ("", "/"):
            raise ValueError("base_url must be an origin without a path prefix")
        self.base_url = urlunsplit((parsed.scheme, parsed.netloc, "", "", ""))
        self.token = token
        self.timeout = float(timeout)
        self.retries = retries
        self.retry_backoff = float(retry_backoff)

    def request(
        self,
        method: str,
        path: str,
        *,
        params: dict[str, Any] | None = None,
        body: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        method = method.upper()
        if method not in {"GET", "POST"}:
            raise ValueError("only GET and POST are supported")
        if not path.startswith("/") or path.startswith("//"):
            raise ValueError("path must be an absolute API path")
        if path.startswith("/api/v1/") is False and path not in {"/health", "/openapi.json"}:
            raise ValueError("path must target a known local API route")
        if params:
            query = urlencode({key: value for key, value in params.items() if value is not None}, doseq=True)
            if query:
                path = f"{path}?{query}"
        data = None if body is None else json.dumps(body, separators=(",", ":")).encode("utf-8")
        headers = {"Accept": "application/json", "Authorization": f"Bearer {self.token}"}
        if data is not None:
            headers["Content-Type"] = "application/json"
        attempts = self.retries + 1 if method == "GET" else 1
        for attempt in range(attempts):
            req = Request(self.base_url + path, data=data, headers=headers, method=method)
            try:
                with urlopen(req, timeout=self.timeout) as response:
                    raw = response.read(1_048_577)
                    if len(raw) > 1_048_576:
                        raise APIProtocolError("API response exceeded 1 MiB")
                    return self._decode(raw)
            except HTTPError as exc:
                payload = self._decode_error_body(exc)
                if method == "GET" and exc.code in self.RETRYABLE_STATUS and attempt + 1 < attempts:
                    self._sleep(attempt)
                    continue
                raise APIResponseError(exc.code, payload) from exc
            except (TimeoutError, socket.timeout) as exc:
                if method == "GET" and attempt + 1 < attempts:
                    self._sleep(attempt)
                    continue
                raise APITimeoutError(f"API request timed out: {path.split('?', 1)[0]}") from exc
            except URLError as exc:
                reason = exc.reason
                is_timeout = isinstance(reason, (TimeoutError, socket.timeout))
                if method == "GET" and attempt + 1 < attempts:
                    self._sleep(attempt)
                    continue
                error_type = APITimeoutError if is_timeout else APIConnectionError
                raise error_type(f"Could not reach local API: {reason}") from exc
        raise APIConnectionError("API request failed after retries")

    def _sleep(self, attempt: int) -> None:
        delay = self.retry_backoff * (2**attempt)
        if delay:
            time.sleep(delay)

    @staticmethod
    def _decode(raw: bytes) -> dict[str, Any]:
        try:
            value = json.loads(raw.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise APIProtocolError("API returned invalid JSON") from exc
        if not isinstance(value, dict):
            raise APIProtocolError("API response must be a JSON object")
        return value

    @classmethod
    def _decode_error_body(cls, error: HTTPError) -> dict[str, Any]:
        try:
            return cls._decode(error.read(1_048_576))
        except APIProtocolError:
            return {"error": f"API returned HTTP {error.code}", "code": "http_error"}

    def health(self) -> dict[str, Any]:
        return self.request("GET", "/health")

    def openapi(self) -> dict[str, Any]:
        return self.request("GET", "/openapi.json")

    def list_targets(self, *, limit: int = 100, offset: int = 0) -> Page:
        return self._page(self.request("GET", "/api/v1/targets", params={"limit": limit, "offset": offset}))

    def list_jobs(self, *, limit: int = 100, offset: int = 0, status: str | None = None, tool: str | None = None) -> Page:
        return self._page(self.request("GET", "/api/v1/jobs", params={"limit": limit, "offset": offset, "status": status, "tool": tool}))

    def list_findings(self, *, limit: int = 100, offset: int = 0, severity: str | None = None, source_tool: str | None = None) -> Page:
        return self._page(self.request("GET", "/api/v1/findings", params={"limit": limit, "offset": offset, "severity": severity, "source_tool": source_tool}))

    @staticmethod
    def _page(data: dict[str, Any]) -> Page:
        try:
            items, total, limit, offset = data["items"], data["total"], data["limit"], data["offset"]
            if not isinstance(items, list) or any(not isinstance(item, dict) for item in items):
                raise TypeError
            if any(not isinstance(value, int) or value < 0 for value in (total, limit, offset)):
                raise TypeError
            return Page(items=items, total=total, limit=limit, offset=offset)
        except (KeyError, TypeError) as exc:
            raise APIProtocolError("API response did not match the pagination schema") from exc

    def get_target(self, target_id: int) -> dict[str, Any]:
        return self._get_detail("targets", target_id)

    def get_job(self, job_id: int) -> dict[str, Any]:
        return self._get_detail("jobs", job_id)

    def get_finding(self, finding_id: int) -> dict[str, Any]:
        return self._get_detail("findings", finding_id)

    def _get_detail(self, resource: str, resource_id: int) -> dict[str, Any]:
        if isinstance(resource_id, bool) or not isinstance(resource_id, int) or resource_id < 1:
            raise ValueError("resource ID must be a positive integer")
        return self.request("GET", f"/api/v1/{resource}/{resource_id}")

    def queue_stats(self) -> dict[str, Any]:
        return self.request("GET", "/api/v1/queue")

    def create_target(self, url: str, *, authorized: bool) -> dict[str, Any]:
        if authorized is not True:
            raise ValueError("authorized=True is required after confirming permission to assess the target")
        if not isinstance(url, str) or not url.strip():
            raise ValueError("url must be a non-empty string")
        return self.request("POST", "/api/v1/targets", body={"url": url, "authorized": True})

    def create_job(self, target_url: str, *, tool: str = "demo") -> dict[str, Any]:
        if not isinstance(target_url, str) or not target_url.strip():
            raise ValueError("target_url must be a non-empty string")
        if not isinstance(tool, str) or not tool.strip():
            raise ValueError("tool must be a non-empty string")
        return self.request("POST", "/api/v1/jobs", body={"target_url": target_url, "tool": tool})


@dataclass(frozen=True)
class APIClientSettings:
    """Validated client settings loaded from environment variables."""

    base_url: str = "http://127.0.0.1:8765"
    timeout: float = 3.0
    retries: int = 2
    retry_backoff: float = 0.15

    @classmethod
    def from_env(cls, environ: dict[str, str] | None = None) -> "APIClientSettings":
        env = os.environ if environ is None else environ
        def number(name: str, default: str, cast):
            raw = env.get(name, default)
            try:
                return cast(raw)
            except (TypeError, ValueError) as exc:
                raise ValueError(f"{name} must be a valid {cast.__name__}") from exc
        settings = cls(
            base_url=env.get("CYBERSEC_API_URL", "http://127.0.0.1:8765"),
            timeout=number("CYBERSEC_API_TIMEOUT", "3.0", float),
            retries=number("CYBERSEC_API_RETRIES", "2", int),
            retry_backoff=number("CYBERSEC_API_RETRY_BACKOFF", "0.15", float),
        )
        # Reuse the client's strict loopback and bounds validation without making a request.
        CyberSecAPIClient(
            settings.base_url, token=env.get("CYBERSEC_API_TOKEN", "configuration-validation-token"),
            timeout=settings.timeout, retries=settings.retries, retry_backoff=settings.retry_backoff,
        )
        return settings


def client_from_env(environ: dict[str, str] | None = None) -> CyberSecAPIClient:
    """Create a configured client from CYBERSEC_API_* environment variables."""
    env = os.environ if environ is None else environ
    token = env.get("CYBERSEC_API_TOKEN", "")
    if not token.strip():
        raise ValueError("CYBERSEC_API_TOKEN must be set to use the remote API client")
    settings = APIClientSettings.from_env(env)
    return CyberSecAPIClient(
        settings.base_url, token=token, timeout=settings.timeout,
        retries=settings.retries, retry_backoff=settings.retry_backoff,
    )
