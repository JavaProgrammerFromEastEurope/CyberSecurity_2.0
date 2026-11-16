"""Loopback-only, token-protected HTTP API for authorized assessment metadata.

Versioned routes live under /api/v1. Legacy unversioned routes remain aliases.
The API queues jobs but deliberately never executes scanners.
"""
from __future__ import annotations

import csv
import hmac
import io
import json
import os
import threading
import time
import uuid
from collections import defaultdict, deque
from dataclasses import asdict
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, urlsplit

from cybersec.repository import Repository

MAX_BODY_BYTES = 1_048_576
ALLOWED_HOSTS = {"127.0.0.1", "localhost", "::1"}
DEFAULT_LIMIT = 100
MAX_LIMIT = 500
API_VERSION = "2.33.0"
RATE_LIMIT_WINDOW_SECONDS = 60.0
RATE_LIMIT_MAX_REQUESTS = 120
_rate_lock = threading.Lock()
_rate_events: dict[str, deque[float]] = defaultdict(deque)


def _json_bytes(value: object) -> bytes:
    return (json.dumps(value, ensure_ascii=False, separators=(",", ":")) + "\n").encode("utf-8")


def _openapi_document() -> dict:
    """Small self-contained OpenAPI 3.1 description for supported routes."""
    protected = [{"BearerAuth": []}]
    page_params = [
        {"name": "limit", "in": "query", "schema": {"type": "integer", "minimum": 1, "maximum": MAX_LIMIT, "default": DEFAULT_LIMIT}},
        {"name": "offset", "in": "query", "schema": {"type": "integer", "minimum": 0, "default": 0}},
    ]
    def list_operation(summary: str, filters: list[dict] | None = None) -> dict:
        return {"get": {"summary": summary, "security": protected, "parameters": page_params + (filters or []),
                         "responses": {"200": {"description": "Paginated results"}, "400": {"description": "Invalid query parameter"}, "401": {"description": "Unauthorized"}}}}
    return {
        "openapi": "3.1.0",
        "info": {"title": "Cyber Security Orchestrator Local API", "version": API_VERSION,
                 "description": "Loopback-only API. Job creation queues metadata only; scanner execution is not exposed."},
        "servers": [{"url": "http://127.0.0.1:8765"}],
        "components": {"securitySchemes": {"BearerAuth": {"type": "http", "scheme": "bearer"}}},
        "paths": {
            "/health": {"get": {"summary": "Public local health check", "responses": {"200": {"description": "Service health"}}}},
            "/openapi.json": {"get": {"summary": "OpenAPI description", "responses": {"200": {"description": "OpenAPI 3.1 document"}}}},
            "/dashboard": {"get": {"summary": "Serve local read-only dashboard UI", "responses": {"200": {"description": "Dashboard HTML"}}}},
            "/api/v1/targets": list_operation("List registered targets"),
            "/api/v1/jobs": list_operation("List queued and historical jobs", [{"name": "status", "in": "query", "schema": {"type": "string"}}, {"name": "tool", "in": "query", "schema": {"type": "string"}}]),
            "/api/v1/findings": list_operation("List normalized findings", [{"name": "severity", "in": "query", "schema": {"type": "string", "enum": ["Critical", "High", "Medium", "Low", "Info"]}}, {"name": "source_tool", "in": "query", "schema": {"type": "string"}}]),
            "/api/v1/risk/intelligence": {"get": {"summary": "Refresh explainable risk signals from stored local findings and remediation metadata", "security": protected, "responses": {"200": {"description": "Detected and persisted risk alerts"}, "401": {"description": "Unauthorized"}}}},
            "/api/v1/risk/alerts": list_operation("Filter persisted risk intelligence alerts by status, type, severity, and priority", [{"name": "status", "in": "query", "schema": {"type": "string", "enum": ["open", "acknowledged", "resolved"]}}, {"name": "alert_type", "in": "query", "schema": {"type": "string"}}, {"name": "severity", "in": "query", "schema": {"type": "string", "enum": ["info", "warning", "high", "critical"]}}, {"name": "priority", "in": "query", "schema": {"type": "string", "enum": ["P1", "P2", "P3", "P4"]}}]),
            "/api/v1/risk/config": {"get": {"summary": "Read risk intelligence rule configuration", "security": protected, "responses": {"200": {"description": "Current rule settings"}}}, "post": {"summary": "Update risk intelligence thresholds", "security": protected, "responses": {"200": {"description": "Updated settings"}, "400": {"description": "Invalid configuration"}}}},
            "/api/v1/risk/policy/status": {"get": {"summary": "Inspect approved active rule versions and configuration drift", "security": protected, "responses": {"200": {"description": "Policy compliance status"}}}},
            "/api/v1/risk/policy/evaluate": {"post": {"summary": "Preview only approved, aligned rules and persist an evaluation record", "security": protected, "responses": {"200": {"description": "Policy evaluation result"}}}},
            "/api/v1/risk/policy/evaluations": {"get": {"summary": "List policy evaluation history", "security": protected, "responses": {"200": {"description": "Policy evaluation history"}}}},
            "/api/v1/risk/policy/evaluations/{evaluation_id}": {"get": {"summary": "Read a policy evaluation record", "security": protected, "responses": {"200": {"description": "Policy evaluation detail"}, "404": {"description": "Evaluation not found"}}}},
            "/api/v1/risk/policy/exceptions": {"get": {"summary": "List temporary policy exceptions", "security": protected, "responses": {"200": {"description": "Exceptions"}}}, "post": {"summary": "Request a temporary policy exception requiring independent review", "security": protected, "responses": {"201": {"description": "Exception requested"}, "400": {"description": "Invalid exception"}}}},
            "/api/v1/risk/policy/exceptions/{exception_id}": {"get": {"summary": "Read a policy exception", "security": protected, "responses": {"200": {"description": "Exception detail"}}}},
            "/api/v1/risk/policy/exceptions/{exception_id}/review": {"post": {"summary": "Approve or reject an exception as its assigned reviewer", "security": protected, "responses": {"200": {"description": "Review recorded"}, "400": {"description": "Invalid review"}}}},
            "/api/v1/risk/policy/exceptions/{exception_id}/revoke": {"post": {"summary": "Revoke a pending or approved exception", "security": protected, "responses": {"200": {"description": "Exception revoked"}}}},
            "/api/v1/risk/policy/exceptions/{exception_id}/audit": {"get": {"summary": "Read exception audit history", "security": protected, "responses": {"200": {"description": "Audit events"}}}},
            "/api/v1/risk/policy/retention": {"get": {"summary": "Read policy evaluation retention settings", "security": protected, "responses": {"200": {"description": "Retention settings"}}}, "post": {"summary": "Set policy evaluation retention days", "security": protected, "responses": {"200": {"description": "Retention updated"}}}},
            "/api/v1/risk/policy/retention/prune": {"post": {"summary": "Preview or delete expired policy evaluation history", "security": protected, "responses": {"200": {"description": "Retention pruning result"}}}},
            "/api/v1/risk/policy/evidence": {"get": {"summary": "List immutable compliance evidence snapshots", "security": protected, "responses": {"200": {"description": "Evidence index"}}}, "post": {"summary": "Create a secret-redacted evidence snapshot from a stored policy evaluation", "security": protected, "responses": {"201": {"description": "Evidence snapshot created"}, "400": {"description": "Invalid evaluation"}}}},
            "/api/v1/risk/policy/evidence/{evidence_id}": {"get": {"summary": "Read a compliance evidence snapshot and verify its digest", "security": protected, "responses": {"200": {"description": "Evidence snapshot"}, "404": {"description": "Evidence not found"}}}},
            "/api/v1/risk/policy/evidence/{evidence_id}/verify": {"get": {"summary": "Verify evidence snapshot SHA-256 integrity", "security": protected, "responses": {"200": {"description": "Integrity result"}}}},
            "/api/v1/risk/policy/evidence/{evidence_id}/report": {"get": {"summary": "Export a compliance report as JSON or CSV rows", "security": protected, "responses": {"200": {"description": "Compliance report"}, "400": {"description": "Invalid format or corrupt evidence"}}}},
            "/api/v1/risk/policy/evidence/{evidence_id}/bundle": {"post": {"summary": "Export a portable evidence bundle with digest manifest and optional HMAC or Ed25519 signature", "security": protected, "responses": {"200": {"description": "Evidence bundle"}, "400": {"description": "Invalid or corrupt evidence"}}}},
            "/api/v1/risk/policy/evidence/bundles/verify": {"post": {"summary": "Verify an evidence bundle using digest, HMAC, or trusted Ed25519 public-key validation", "security": protected, "responses": {"200": {"description": "Bundle verification result"}, "400": {"description": "Invalid bundle"}}}},
            "/api/v1/risk/policy/evidence/custody": {"get": {"summary": "List evidence bundle chain-of-custody events", "security": protected, "responses": {"200": {"description": "Custody events"}}}},
            "/api/v1/risk/policy/evidence/custody/verify": {"get": {"summary": "Verify the custody event hash chain", "security": protected, "responses": {"200": {"description": "Custody chain verification"}}}},
            "/api/v1/risk/policy/evidence/custody/checkpoints": {"get": {"summary": "List signed custody checkpoints", "security": protected, "responses": {"200": {"description": "Checkpoint index"}}}, "post": {"summary": "Create an Ed25519-signed custody checkpoint for external storage", "security": protected, "responses": {"201": {"description": "Signed checkpoint"}, "400": {"description": "Invalid signing key or chain"}}}},
            "/api/v1/risk/policy/evidence/custody/checkpoints/verify": {"post": {"summary": "Verify a signed checkpoint and anchored custody-chain prefix", "security": protected, "responses": {"200": {"description": "Checkpoint verification"}, "400": {"description": "Invalid checkpoint"}}}},
            "/api/v1/risk/policy/evidence/signing-keys": {"get": {"summary": "List trusted Ed25519 public keys", "security": protected, "responses": {"200": {"description": "Trusted public keys"}}}, "post": {"summary": "Register a trusted Ed25519 public key", "security": protected, "responses": {"201": {"description": "Public key registered"}, "400": {"description": "Invalid key"}}}},
            "/api/v1/risk/policy/evidence/signing-keys/rotate": {"post": {"summary": "Atomically register a replacement Ed25519 key and revoke the previous key", "security": protected, "responses": {"200": {"description": "Key rotation completed"}, "400": {"description": "Invalid rotation request"}}}},
            "/api/v1/risk/policy/evidence/signing-keys/{key_id}/revoke": {"post": {"summary": "Revoke a trusted Ed25519 signing key", "security": protected, "responses": {"200": {"description": "Key revoked"}, "400": {"description": "Invalid key or reason"}}}},
            "/api/v1/risk/policy/evidence/signing-keys/{key_id}/audit": {"get": {"summary": "Read signing-key registration and revocation audit events", "security": protected, "responses": {"200": {"description": "Key audit events"}}}},
            "/api/v1/risk/rules": {"get": {"summary": "List named risk rule sets and optional audit history", "security": protected, "responses": {"200": {"description": "Rule sets"}}}, "post": {"summary": "Create or update a named risk rule set", "security": protected, "responses": {"200": {"description": "Rule saved"}, "400": {"description": "Invalid rule"}}}},
            "/api/v1/risk/rules/compare": {"get": {"summary": "Compare 2 to 10 named rule sets against identical stored metadata without persistence", "security": protected, "parameters": [{"name": "ids", "in": "query", "required": True, "schema": {"type": "string", "example": "1,2"}}], "responses": {"200": {"description": "Rule comparison"}, "400": {"description": "Invalid rule IDs"}}}},
            "/api/v1/risk/rules/{rule_id}/enabled": {"post": {"summary": "Enable or disable a named risk rule", "security": protected, "responses": {"200": {"description": "Rule updated"}, "400": {"description": "Invalid rule"}}}},
            "/api/v1/risk/rules/export": {"get": {"summary": "Export risk-rule configurations with SHA-256 integrity digest", "security": protected, "responses": {"200": {"description": "Integrity-checked export bundle"}}}},
            "/api/v1/risk/rules/import": {"post": {"summary": "Validate and import a risk-rule configuration bundle", "security": protected, "responses": {"200": {"description": "Import result"}, "400": {"description": "Invalid or tampered bundle"}}}},
            "/api/v1/risk/rules/{rule_id}/governance": {"get": {"summary": "Read active version and approval state", "security": protected, "responses": {"200": {"description": "Governance state"}}}},
            "/api/v1/risk/rules/{rule_id}/approve": {"post": {"summary": "Approve the active version and optionally lock the rule", "security": protected, "responses": {"200": {"description": "Approval recorded"}}}},
            "/api/v1/risk/rules/{rule_id}/unlock": {"post": {"summary": "Unlock a governed rule with an audit reason", "security": protected, "responses": {"200": {"description": "Rule unlocked"}}}},
            "/api/v1/risk/rules/{rule_id}/active-version": {"post": {"summary": "Designate the active immutable rule version", "security": protected, "responses": {"200": {"description": "Active version changed"}}}},
            "/api/v1/risk/rules/{rule_id}/governance-audit": {"get": {"summary": "Read approval and unlock audit events", "security": protected, "responses": {"200": {"description": "Governance audit"}}}},
            "/api/v1/risk/rules/{rule_id}/versions/{before}/compare/{after}": {"get": {"summary": "Compare outcomes from two versions against the same stored metadata", "security": protected, "responses": {"200": {"description": "Before and after outcome preview"}}}},
            "/api/v1/risk/rules/{rule_id}/versions": {"get": {"summary": "List immutable versions of a risk rule", "security": protected, "responses": {"200": {"description": "Rule versions"}, "404": {"description": "Rule not found"}}}},
            "/api/v1/risk/rules/{rule_id}/rollback": {"post": {"summary": "Restore a risk rule version as a new version", "security": protected, "responses": {"200": {"description": "Rule rolled back"}, "400": {"description": "Invalid version"}}}},
            "/api/v1/risk/comparison-history": list_operation("List saved risk-rule comparison summaries"),
            "/api/v1/risk/comparison-history/{comparison_id}": {"get": {"summary": "Read a saved risk-rule comparison result", "security": protected, "responses": {"200": {"description": "Comparison details"}, "404": {"description": "Comparison not found"}}}},
            "/api/v1/risk/intelligence/preview": {"get": {"summary": "Preview rules against stored data without persisting alerts", "security": protected, "responses": {"200": {"description": "Non-persistent rule preview"}, "400": {"description": "Invalid configuration"}}}},
            "/api/v1/risk/alerts/{alert_id}/acknowledge": {"post": {"summary": "Acknowledge a risk intelligence alert as an analyst", "security": protected, "responses": {"200": {"description": "Alert acknowledged"}, "400": {"description": "Invalid acknowledgement"}, "404": {"description": "Alert not found"}}}},
            "/api/v1/risk/summary": {"get": {"summary": "Explainable risk prioritization of stored findings", "security": protected, "responses": {"200": {"description": "Risk summary"}, "400": {"description": "Invalid limit"}, "401": {"description": "Unauthorized"}}}},
            "/api/v1/portfolio/report": {"get": {"summary": "Multi-target risk portfolio report", "security": protected, "responses": {"200": {"description": "Portfolio report"}, "400": {"description": "Invalid limit"}, "401": {"description": "Unauthorized"}}}},
            "/api/v1/risk/contextual": {"get": {"summary": "Contextual risk ranking using stored metadata", "security": protected, "responses": {"200": {"description": "Contextual risk ranking"}, "400": {"description": "Invalid limit"}, "401": {"description": "Unauthorized"}}}},
            "/api/v1/targets/{target_id}/criticality": {"post": {"summary": "Set analyst-assigned target business criticality", "security": protected, "responses": {"200": {"description": "Updated target"}, "400": {"description": "Invalid criticality"}, "404": {"description": "Target not found"}}}},
            "/api/v1/queue": {"get": {"summary": "Notification queue statistics", "security": protected, "responses": {"200": {"description": "Queue statistics"}, "401": {"description": "Unauthorized"}}}},
            "/api/v1/remediation": list_operation("List remediation tasks", [{"name": "status", "in": "query", "schema": {"type": "string", "enum": ["open", "in_progress", "blocked", "resolved", "accepted"]}}, {"name": "overdue", "in": "query", "schema": {"type": "boolean"}}]),
            "/api/v1/remediation/summary": {"get": {"summary": "Remediation task counts and overdue total", "security": protected, "responses": {"200": {"description": "Remediation summary"}, "401": {"description": "Unauthorized"}}}},
            "/api/v1/remediation/sla": {"get": {"summary": "SLA status summary and policy", "security": protected, "responses": {"200": {"description": "SLA summary"}, "401": {"description": "Unauthorized"}}}},
            "/api/v1/remediation/sla-policy": {"post": {"summary": "Set SLA days for a severity", "security": protected, "responses": {"200": {"description": "SLA policy updated"}, "400": {"description": "Invalid policy"}, "401": {"description": "Unauthorized"}}}},
            "/api/v1/remediation/history": list_operation("List remediation audit history", [{"name": "task_id", "in": "query", "schema": {"type": "integer", "minimum": 1}}]),
            "/api/v1/remediation/verification-summary": {"get": {"summary": "Latest verification outcomes across remediation tasks", "security": protected, "responses": {"200": {"description": "Verification summary"}, "401": {"description": "Unauthorized"}}}},
            "/api/v1/remediation/metrics": {"get": {"summary": "Remediation performance KPIs for an optional inclusive date range", "security": protected, "parameters": [{"name": "start_date", "in": "query", "schema": {"type": "string", "format": "date"}}, {"name": "end_date", "in": "query", "schema": {"type": "string", "format": "date"}}], "responses": {"200": {"description": "JSON remediation metrics report"}, "400": {"description": "Invalid date range"}, "401": {"description": "Unauthorized"}}}},
            "/api/v1/remediation/metrics.csv": {"get": {"summary": "Export per-task remediation performance metrics as CSV", "security": protected, "parameters": [{"name": "start_date", "in": "query", "schema": {"type": "string", "format": "date"}}, {"name": "end_date", "in": "query", "schema": {"type": "string", "format": "date"}}], "responses": {"200": {"description": "CSV remediation metrics export"}, "400": {"description": "Invalid date range"}, "401": {"description": "Unauthorized"}}}},
            "/api/v1/remediation/trends": {"get": {"summary": "Daily remediation flow and equal-length period comparison", "security": protected, "parameters": [{"name": "start_date", "in": "query", "schema": {"type": "string", "format": "date"}}, {"name": "end_date", "in": "query", "schema": {"type": "string", "format": "date"}}], "responses": {"200": {"description": "Trend and previous-period comparison"}, "400": {"description": "Invalid date range"}, "401": {"description": "Unauthorized"}}}},
            "/api/v1/remediation/trend-snapshots": {"get": {"summary": "List saved remediation trend snapshots", "security": protected, "responses": {"200": {"description": "Snapshot list"}, "401": {"description": "Unauthorized"}}}, "post": {"summary": "Save a snapshot of current remediation trends", "security": protected, "responses": {"201": {"description": "Snapshot saved"}, "400": {"description": "Invalid date range"}, "401": {"description": "Unauthorized"}}}},
            "/api/v1/remediation/trend-snapshots/{snapshot_id}": {"get": {"summary": "Read a saved remediation trend snapshot", "security": protected, "responses": {"200": {"description": "Snapshot details"}, "404": {"description": "Snapshot not found"}}}},
            "/api/v1/remediation/{task_id}/verification": {"get": {"summary": "List verification history for a remediation task", "security": protected, "responses": {"200": {"description": "Verification history"}, "404": {"description": "Task not found"}}}, "post": {"summary": "Record verification outcome and evidence", "security": protected, "responses": {"200": {"description": "Verification recorded"}, "400": {"description": "Invalid verification"}, "404": {"description": "Task not found"}}}},
            "/api/v1/findings/{finding_id}/remediation": {"post": {"summary": "Create or update a remediation task for a finding", "security": protected, "parameters": [{"name": "finding_id", "in": "path", "required": True, "schema": {"type": "integer", "minimum": 1}}], "responses": {"200": {"description": "Remediation task saved"}, "400": {"description": "Invalid remediation data"}, "404": {"description": "Finding not found"}}}},
            "/api/v1/comparisons": list_operation("List saved offline scan comparisons"),
            "/api/v1/comparisons/{comparison_id}": {"get": {"summary": "Get a saved offline comparison", "security": protected, "parameters": [{"name": "comparison_id", "in": "path", "required": True, "schema": {"type": "integer", "minimum": 1}}], "responses": {"200": {"description": "Comparison details"}, "404": {"description": "Comparison not found"}}}},
            "/api/v1/targets/{target_id}": {"get": {"summary": "Get one target", "security": protected, "parameters": [{"name": "target_id", "in": "path", "required": True, "schema": {"type": "integer", "minimum": 1}}], "responses": {"200": {"description": "Target details"}, "404": {"description": "Target not found"}}}},
            "/api/v1/targets/{target_id}/report": {"get": {"summary": "Read-only target report with jobs, findings and daily trend", "security": protected, "parameters": [{"name": "target_id", "in": "path", "required": True, "schema": {"type": "integer", "minimum": 1}}], "responses": {"200": {"description": "Target report"}, "404": {"description": "Target not found"}}}},
            "/api/v1/jobs/{job_id}": {"get": {"summary": "Get one job", "security": protected, "parameters": [{"name": "job_id", "in": "path", "required": True, "schema": {"type": "integer", "minimum": 1}}], "responses": {"200": {"description": "Job details"}, "404": {"description": "Job not found"}}}},
            "/api/v1/findings/{finding_id}": {"get": {"summary": "Get one finding", "security": protected, "parameters": [{"name": "finding_id", "in": "path", "required": True, "schema": {"type": "integer", "minimum": 1}}], "responses": {"200": {"description": "Finding details"}, "404": {"description": "Finding not found"}}}},
            "/api/v1/targets": {"get": list_operation("List registered targets"), "post": {"summary": "Register a target after confirming authorization", "security": protected, "responses": {"201": {"description": "Target created"}, "403": {"description": "Authorization confirmation required"}}}},
            "/api/v1/jobs": {"get": list_operation("List jobs", [{"name": "status", "in": "query", "schema": {"type": "string"}}, {"name": "tool", "in": "query", "schema": {"type": "string"}}]), "post": {"summary": "Queue a job without executing scanners", "security": protected, "responses": {"201": {"description": "Queued job"}, "400": {"description": "Invalid job"}}}},
        },
    }


def make_handler(repo: Repository, token: str):
    rate_namespace = uuid.uuid4().hex

    class APIHandler(BaseHTTPRequestHandler):
        server_version = "CyberSecLocalAPI/2.33"
        sys_version = ""

        def log_message(self, fmt: str, *args) -> None:
            print(f"cybersec-api client={self.client_address[0]} message={fmt % args}")

        def _begin_request(self) -> bool:
            self._request_id = uuid.uuid4().hex
            now = time.monotonic()
            client = self.client_address[0] if self.client_address else "unknown"
            # Throttle each client within this handler/server instance; independent local
            # instances must not consume one another's request budget.
            key = f"{client}:{rate_namespace}"
            with _rate_lock:
                events = _rate_events[key]
                while events and now - events[0] >= RATE_LIMIT_WINDOW_SECONDS:
                    events.popleft()
                if len(events) >= RATE_LIMIT_MAX_REQUESTS:
                    self._send(429, {"error": "Rate limit exceeded", "code": "rate_limit_exceeded"})
                    return False
                events.append(now)
            return True

        def _error(self, status: int, message: str, code: str) -> None:
            self._send(status, {"error": message, "code": code})

        def _send_dashboard(self) -> None:
            from cybersec.dashboard import dashboard_bytes
            payload = dashboard_bytes()
            self.send_response(200)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.send_header("Content-Length", str(len(payload)))
            self.send_header("Cache-Control", "no-store")
            self.send_header("X-Content-Type-Options", "nosniff")
            self.send_header("X-Frame-Options", "DENY")
            self.send_header("Referrer-Policy", "no-referrer")
            self.send_header("Content-Security-Policy", "default-src 'none'; script-src 'unsafe-inline'; style-src 'unsafe-inline'; connect-src 'self'; img-src 'none'; base-uri 'none'; form-action 'none'; frame-ancestors 'none'")
            self.end_headers()
            self.wfile.write(payload)

        def _send_csv(self, status: int, content: str, filename: str) -> None:
            payload = content.encode("utf-8-sig")
            self.send_response(status)
            self.send_header("Content-Type", "text/csv; charset=utf-8")
            self.send_header("Content-Disposition", f'attachment; filename="{filename}"')
            self.send_header("Content-Length", str(len(payload)))
            self.send_header("Cache-Control", "no-store")
            self.send_header("X-Request-ID", getattr(self, "_request_id", "unavailable"))
            self.send_header("X-Content-Type-Options", "nosniff")
            self.send_header("X-Frame-Options", "DENY")
            self.send_header("Content-Security-Policy", "default-src 'none'")
            self.end_headers()
            self.wfile.write(payload)

        def _send(self, status: int, data: object) -> None:
            response_path = urlsplit(getattr(self, "path", "")).path
            is_portable_bundle = __import__("re").fullmatch(r"(?:/api/v1)?/risk/policy/evidence/[0-9]+/bundle", response_path) is not None
            if isinstance(data, dict) and response_path != "/openapi.json" and not is_portable_bundle:
                data = {**data, "request_id": getattr(self, "_request_id", "unavailable")}
            payload = _json_bytes(data)
            self.send_response(status)
            self.send_header("Content-Type", "application/json; charset=utf-8")
            self.send_header("Content-Length", str(len(payload)))
            self.send_header("Cache-Control", "no-store")
            self.send_header("X-Request-ID", getattr(self, "_request_id", "unavailable"))
            self.send_header("X-Content-Type-Options", "nosniff")
            self.send_header("X-Frame-Options", "DENY")
            self.send_header("Content-Security-Policy", "default-src 'none'")
            self.end_headers()
            self.wfile.write(payload)

        def _authorized(self) -> bool:
            supplied = self.headers.get("Authorization", "")
            prefix = "Bearer "
            candidate = supplied[len(prefix):] if supplied.startswith(prefix) else ""
            return bool(candidate) and hmac.compare_digest(candidate, token)

        def _body(self) -> dict:
            content_type = self.headers.get("Content-Type", "").split(";", 1)[0].strip().lower()
            if content_type != "application/json":
                raise ValueError("Content-Type must be application/json")
            raw_length = self.headers.get("Content-Length", "0")
            try:
                length = int(raw_length)
            except ValueError as exc:
                raise ValueError("Invalid Content-Length") from exc
            if length < 0 or length > MAX_BODY_BYTES:
                raise ValueError("Request body must be at most 1 MiB")
            raw = self.rfile.read(length)
            try:
                value = json.loads(raw.decode("utf-8"))
            except (UnicodeDecodeError, json.JSONDecodeError) as exc:
                raise ValueError("Request body must be valid UTF-8 JSON") from exc
            if not isinstance(value, dict):
                raise ValueError("Request JSON must be an object")
            return value

        def _path_and_query(self) -> tuple[str, dict[str, list[str]]]:
            parsed = urlsplit(self.path)
            path = parsed.path
            if path.startswith("/api/v1/"):
                path = path[len("/api/v1"):]
            return path, parse_qs(parsed.query, keep_blank_values=True)

        @staticmethod
        def _single(query: dict[str, list[str]], name: str, default: str | None = None) -> str | None:
            values = query.get(name)
            if not values:
                return default
            if len(values) != 1:
                raise ValueError(f"Query parameter '{name}' must appear once")
            return values[0]

        def _page(self, query: dict[str, list[str]], items: list[dict]) -> dict:
            try:
                raw_limit = self._single(query, "limit", str(DEFAULT_LIMIT))
                raw_offset = self._single(query, "offset", "0")
                limit, offset = int(raw_limit), int(raw_offset)
            except (TypeError, ValueError) as exc:
                raise ValueError("limit and offset must be integers") from exc
            if not 1 <= limit <= MAX_LIMIT:
                raise ValueError(f"limit must be between 1 and {MAX_LIMIT}")
            if offset < 0:
                raise ValueError("offset must be zero or greater")
            total = len(items)
            return {"items": items[offset:offset + limit], "total": total, "limit": limit, "offset": offset}

        def do_GET(self) -> None:  # noqa: N802
            if not self._begin_request():
                return
            path, query = self._path_and_query()
            if path == "/health":
                self._send(200, {"ok": True, "service": "cybersec-local-api", "version": API_VERSION})
                return
            if path == "/dashboard":
                self._send_dashboard()
                return
            if path == "/openapi.json":
                self._send(200, _openapi_document())
                return
            if not self._authorized():
                self._error(401, "Bearer token required", "unauthorized")
                return
            try:
                if path == "/risk/policy/evidence/custody/checkpoints":
                    raw_limit = self._single(query, "limit", "100")
                    self._send(200, repo.list_risk_policy_evidence_custody_checkpoints(limit=int(raw_limit))); return
                if path == "/risk/policy/evidence/custody":
                    raw_limit = self._single(query, "limit", "100")
                    self._send(200, repo.list_risk_policy_evidence_custody(limit=int(raw_limit))); return
                if path == "/risk/policy/evidence/custody/verify":
                    self._send(200, repo.verify_risk_policy_evidence_custody_chain()); return
                if path == "/risk/policy/evidence/custody/checkpoints":
                    result = repo.create_risk_policy_evidence_custody_checkpoint(body.get("key_id", ""), body.get("signing_private_key", ""), body.get("actor", "security-auditor"))
                    self._send(201, result); return
                if path == "/risk/policy/evidence/custody/checkpoints/verify":
                    result = repo.verify_risk_policy_evidence_custody_checkpoint(body.get("checkpoint"), body.get("trusted_public_key"))
                    self._send(200, result); return
                if path == "/risk/policy/evidence/signing-keys":
                    include_revoked = self._single(query, "include_revoked", "true").lower() not in {"0", "false", "no"}
                    self._send(200, repo.list_risk_policy_evidence_signing_keys(include_revoked)); return
                key_audit_match = __import__("re").fullmatch(r"/risk/policy/evidence/signing-keys/([A-Za-z0-9._-]{1,100})/audit", path)
                if key_audit_match:
                    self._send(200, repo.list_risk_policy_evidence_signing_key_audit(key_audit_match.group(1))); return
                if path == "/risk/policy/evidence":
                    raw_limit = self._single(query, "limit", "50")
                    raw_evaluation = self._single(query, "evaluation_id")
                    self._send(200, repo.list_risk_policy_evidence(int(raw_limit), None if raw_evaluation is None else int(raw_evaluation))); return
                if path == "/risk/policy/evidence/bundles/verify":
                    self._error(405, "Use POST to verify an evidence bundle", "method_not_allowed"); return
                evidence_match = __import__("re").fullmatch(r"/risk/policy/evidence/([0-9]+)(?:/(verify|report|bundle))?", path)
                if evidence_match:
                    evidence_id = int(evidence_match.group(1)); action = evidence_match.group(2)
                    if action == "verify": self._send(200, repo.verify_risk_policy_evidence(evidence_id)); return
                    if action == "report": self._send(200, repo.export_risk_policy_compliance_report(evidence_id, self._single(query, "format", "json"))); return
                    if action == "bundle": self._send(405, {"error": "method_not_allowed", "message": "Use POST to export an evidence bundle"}); return
                    self._send(200, repo.get_risk_policy_evidence(evidence_id)); return
                if path == "/risk/policy/exceptions":
                    raw_limit = self._single(query, "limit", "100")
                    raw_rule = self._single(query, "rule_id")
                    self._send(200, repo.list_risk_policy_exceptions(None if raw_rule is None else int(raw_rule), int(raw_limit))); return
                if path == "/risk/policy/retention":
                    self._send(200, repo.get_risk_policy_retention()); return
                exception_match = __import__("re").fullmatch(r"/risk/policy/exceptions/([0-9]+)(?:/(audit))?", path)
                if exception_match:
                    exception_id = int(exception_match.group(1))
                    if exception_match.group(2) == "audit": self._send(200, repo.list_risk_policy_exception_audit(exception_id)); return
                    self._send(200, repo.get_risk_policy_exception(exception_id)); return
                if path == "/risk/policy/status":
                    self._send(200, repo.get_risk_intelligence_policy_status()); return
                if path == "/risk/policy/evaluations":
                    raw_limit = self._single(query, "limit", "50")
                    try: limit = int(raw_limit)
                    except ValueError as exc: raise ValueError("limit must be an integer") from exc
                    self._send(200, repo.list_risk_intelligence_policy_evaluations(limit)); return
                policy_evaluation = __import__("re").fullmatch(r"/risk/policy/evaluations/([0-9]+)", path)
                if policy_evaluation:
                    self._send(200, repo.get_risk_intelligence_policy_evaluation(int(policy_evaluation.group(1)))); return
                if path == "/risk/rules":
                    include_audit = self._single(query, "audit", "false").lower() == "true"
                    self._send(200, repo.list_risk_intelligence_rules(include_audit=include_audit))
                    return
                if path == "/risk/rules/export":
                    raw_ids = self._single(query, "ids")
                    ids = None if not raw_ids else [int(v.strip()) for v in raw_ids.split(",") if v.strip()]
                    self._send(200, repo.export_risk_intelligence_rules(ids)); return
                governance = __import__("re").fullmatch(r"/risk/rules/([0-9]+)/governance", path)
                if governance:
                    self._send(200, repo.get_risk_intelligence_governance(int(governance.group(1)))); return
                governance_audit = __import__("re").fullmatch(r"/risk/rules/([0-9]+)/governance-audit", path)
                if governance_audit:
                    raw_limit=self._single(query,"limit","100")
                    self._send(200,repo.list_risk_intelligence_governance_audit(int(governance_audit.group(1)),int(raw_limit))); return
                version_compare = __import__("re").fullmatch(r"/risk/rules/([0-9]+)/versions/([0-9]+)/compare/([0-9]+)", path)
                if version_compare:
                    self._send(200,repo.compare_risk_intelligence_rule_versions(int(version_compare.group(1)),int(version_compare.group(2)),int(version_compare.group(3)))); return
                rule_versions = __import__("re").fullmatch(r"/risk/rules/([0-9]+)/versions", path)
                if rule_versions:
                    rule_id = int(rule_versions.group(1))
                    if rule_id < 1: raise ValueError("Resource ID must be a positive integer")
                    self._send(200, repo.list_risk_intelligence_rule_versions(rule_id))
                    return
                if path == "/risk/comparison-history":
                    raw_limit = self._single(query, "limit", "50")
                    try: limit = int(raw_limit)
                    except ValueError as exc: raise ValueError("limit must be an integer") from exc
                    self._send(200, repo.list_risk_intelligence_comparison_history(limit))
                    return
                comparison_detail = __import__("re").fullmatch(r"/risk/comparison-history/([0-9]+)", path)
                if comparison_detail:
                    comparison_id = int(comparison_detail.group(1))
                    self._send(200, repo.get_risk_intelligence_comparison(comparison_id))
                    return
                if path == "/risk/rules/compare":
                    raw_ids = self._single(query, "ids", "")
                    try:
                        ids = [int(value.strip()) for value in raw_ids.split(",") if value.strip()]
                    except ValueError as exc:
                        raise ValueError("ids must be comma-separated positive integers") from exc
                    self._send(200, repo.compare_risk_intelligence_rules(ids, self._single(query, "actor", "analyst")))
                    return
                if path == "/risk/config":
                    self._send(200, repo.get_risk_intelligence_config())
                    return
                if path in {"/risk/intelligence", "/risk/intelligence/preview"}:
                    preview_config = None
                    if path.endswith("/preview"):
                        preview_config = {}
                        for key in ("window_days", "minimum_findings"):
                            value = self._single(query, key)
                            if value is not None:
                                try: preview_config[key] = int(value)
                                except ValueError as exc: raise ValueError(f"{key} must be an integer") from exc
                        value = self._single(query, "growth_ratio")
                        if value is not None:
                            try: preview_config["growth_ratio"] = float(value)
                            except ValueError as exc: raise ValueError("growth_ratio must be numeric") from exc
                        value = self._single(query, "criticality_boost")
                        if value is not None:
                            if value.lower() not in {"true", "false"}: raise ValueError("criticality_boost must be true or false")
                            preview_config["criticality_boost"] = value.lower() == "true"
                    self._send(200, repo.refresh_risk_intelligence(preview_config, persist=not path.endswith("/preview")))
                    return
                if path == "/risk/alerts":
                    raw_limit = self._single(query, "limit", "100")
                    try:
                        limit = int(raw_limit)
                    except (TypeError, ValueError) as exc:
                        raise ValueError("limit must be an integer") from exc
                    self._send(200, repo.list_risk_intelligence_alerts(self._single(query, "status"), limit,
                        alert_type=self._single(query, "alert_type"), severity=self._single(query, "severity"), priority=self._single(query, "priority")))
                    return
                if path == "/remediation/summary":
                    self._send(200, repo.remediation_summary())
                    return
                if path == "/remediation/sla":
                    self._send(200, repo.remediation_sla_summary())
                    return
                if path == "/remediation/verification-summary":
                    self._send(200, repo.remediation_verification_summary())
                    return
                verification_match = __import__("re").fullmatch(r"/remediation/([0-9]+)/verification", path)
                if verification_match:
                    task_id = int(verification_match.group(1))
                    if task_id < 1:
                        raise ValueError("Resource ID must be a positive integer")
                    history = repo.remediation_verification_history(task_id)
                    self._send(200, {"items": history, "total": len(history)})
                    return
                if path == "/remediation/history":
                    raw_task_id = self._single(query, "task_id")
                    try:
                        task_id = int(raw_task_id) if raw_task_id is not None else None
                    except ValueError as exc:
                        raise ValueError("task_id must be an integer") from exc
                    if task_id is not None and task_id < 1:
                        raise ValueError("task_id must be positive")
                    self._send(200, self._page(query, repo.remediation_history(task_id)))
                    return
                if path == "/remediation/trends":
                    self._send(200, repo.remediation_trends(start_date=self._single(query, "start_date"), end_date=self._single(query, "end_date")))
                    return
                if path == "/remediation/trend-snapshots":
                    raw_limit = self._single(query, "limit", "100")
                    try:
                        limit = int(raw_limit)
                    except (TypeError, ValueError) as exc:
                        raise ValueError("limit must be an integer") from exc
                    self._send(200, {"items": repo.list_remediation_trend_snapshots(limit), "total": len(repo.list_remediation_trend_snapshots(limit))})
                    return
                snapshot_match = __import__("re").fullmatch(r"/remediation/trend-snapshots/([0-9]+)", path)
                if snapshot_match:
                    snapshot_id = int(snapshot_match.group(1))
                    if snapshot_id < 1:
                        raise ValueError("Resource ID must be a positive integer")
                    self._send(200, repo.get_remediation_trend_snapshot(snapshot_id))
                    return
                if path in {"/remediation/metrics", "/remediation/metrics.csv"}:
                    start_date = self._single(query, "start_date")
                    end_date = self._single(query, "end_date")
                    report = repo.remediation_metrics(start_date=start_date, end_date=end_date)
                    if path.endswith(".csv"):
                        output = io.StringIO(newline="")
                        fields = ["task_id", "finding_id", "status", "severity", "finding_title", "target_id",
                                  "target_url", "assignee", "created_at", "resolved_at", "resolution_days",
                                  "sla_days", "sla_due_date", "sla_met", "latest_verification"]
                        writer = csv.DictWriter(output, fieldnames=fields, extrasaction="ignore")
                        writer.writeheader()
                        for row in report["tasks"]:
                            writer.writerow(row)
                        self._send_csv(200, output.getvalue(), "cybersec-remediation-metrics.csv")
                    else:
                        self._send(200, report)
                    return
                if path == "/remediation":
                    status_filter = self._single(query, "status")
                    overdue_value = self._single(query, "overdue", "false")
                    if overdue_value not in {"true", "false", "1", "0"}:
                        raise ValueError("overdue must be true or false")
                    items = repo.list_remediation_tasks(status=status_filter, overdue_only=overdue_value in {"true", "1"})
                    self._send(200, self._page(query, items))
                    return
                if path in {"/risk/summary", "/portfolio/report", "/risk/contextual"}:
                    raw_limit = self._single(query, "limit", "1000")
                    try:
                        limit = int(raw_limit)
                    except (TypeError, ValueError) as exc:
                        raise ValueError("limit must be an integer") from exc
                    from cybersec.risk_analytics import build_portfolio_report, build_risk_summary
                    if path == "/risk/contextual":
                        from cybersec.contextual_risk import build_contextual_risk
                        self._send(200, build_contextual_risk(repo, limit=limit))
                    else:
                        builder = build_risk_summary if path == "/risk/summary" else build_portfolio_report
                        self._send(200, builder(repo, limit=limit))
                    return
                report_match = __import__("re").fullmatch(r"/targets/([0-9]+)/report", path)
                if report_match:
                    target_id = int(report_match.group(1))
                    if target_id < 1:
                        raise ValueError("Resource ID must be a positive integer")
                    target = repo.get_target_by_id(target_id)
                    if target is None:
                        self._error(404, "Target not found", "not_found")
                        return
                    jobs = [asdict(job) for job in repo.list_jobs() if job.target_id == target_id]
                    findings = [finding.to_dict() for finding in repo.list_findings() if finding.target_id == target_id]
                    severity_levels = ["Critical", "High", "Medium", "Low", "Info"]
                    severity = {level: sum(1 for finding in findings if finding.get("severity") == level) for level in severity_levels}
                    daily = {}
                    for finding in findings:
                        day = str(finding.get("created_at", ""))[:10] or "Unknown"
                        daily.setdefault(day, {"date": day, "total": 0, **{level: 0 for level in severity_levels}})
                        daily[day]["total"] += 1
                        level = finding.get("severity")
                        if level in severity_levels:
                            daily[day][level] += 1
                    self._send(200, {"target": asdict(target), "jobs": jobs, "findings": findings,
                                     "summary": {"job_count": len(jobs), "finding_count": len(findings), "severity": severity},
                                     "daily_trend": [daily[key] for key in sorted(daily)]})
                    return
                detail = __import__("re").fullmatch(r"/(targets|jobs|findings|comparisons)/([0-9]+)", path)
                if detail:
                    kind, raw_id = detail.groups()
                    record_id = int(raw_id)
                    if record_id < 1:
                        raise ValueError("Resource ID must be a positive integer")
                    if kind == "targets":
                        item = repo.get_target_by_id(record_id)
                        data = asdict(item) if item else None
                    elif kind == "jobs":
                        item = repo.get_job(record_id)
                        data = asdict(item) if item else None
                    elif kind == "findings":
                        item = next((x for x in repo.list_findings() if x.id == record_id), None)
                        data = item.to_dict() if item else None
                    else:
                        data = repo.get_comparison(record_id)
                    if data is None:
                        self._error(404, f"{kind[:-1].capitalize()} not found", "not_found")
                    else:
                        self._send(200, data)
                elif path == "/targets":
                    items = [asdict(x) for x in repo.list_targets()]
                    self._send(200, self._page(query, items))
                elif path == "/jobs":
                    items = [asdict(x) for x in repo.list_jobs()]
                    status_filter = self._single(query, "status")
                    tool_filter = self._single(query, "tool")
                    if status_filter is not None:
                        items = [x for x in items if x["status"].casefold() == status_filter.casefold()]
                    if tool_filter is not None:
                        items = [x for x in items if x["tool"].casefold() == tool_filter.casefold()]
                    self._send(200, self._page(query, items))
                elif path == "/findings":
                    items = [x.to_dict() for x in repo.list_findings()]
                    severity = self._single(query, "severity")
                    source_tool = self._single(query, "source_tool")
                    if severity is not None:
                        items = [x for x in items if x["severity"].casefold() == severity.casefold()]
                    if source_tool is not None:
                        items = [x for x in items if source_tool.casefold() in {part.strip().casefold() for part in x["source_tool"].split(",")}]
                    self._send(200, self._page(query, items))
                elif path == "/queue":
                    from cybersec.delivery_queue import queue_stats
                    self._send(200, queue_stats(repo))
                elif path == "/comparisons":
                    items = repo.list_comparisons(limit=1000)
                    self._send(200, self._page(query, items))
                else:
                    self._error(404, "Not found", "not_found")
            except PermissionError as exc:
                self._error(409, str(exc), "governance_locked")
            except ValueError as exc:
                self._error(400, str(exc), "invalid_request")

        def do_POST(self) -> None:  # noqa: N802
            if not self._begin_request():
                return
            path, _query = self._path_and_query()
            if not self._authorized():
                self._error(401, "Bearer token required", "unauthorized")
                return
            try:
                body = self._body()
                if path == "/risk/policy/evidence/custody/checkpoints":
                    result = repo.create_risk_policy_evidence_custody_checkpoint(body.get("key_id", ""), body.get("signing_private_key", ""), body.get("actor", "security-auditor"))
                    self._send(201, result); return
                if path == "/risk/policy/evidence/custody/checkpoints/verify":
                    result = repo.verify_risk_policy_evidence_custody_checkpoint(body.get("checkpoint"), body.get("trusted_public_key"))
                    self._send(200, result); return
                if path == "/risk/policy/evidence/signing-keys/rotate":
                    result = repo.rotate_risk_policy_evidence_signing_key(body.get("old_key_id", ""), body.get("new_key_id", ""), body.get("new_public_key", ""), body.get("actor", "security-admin"), body.get("reason", "planned rotation"))
                    self._send(200, result); return
                if path == "/risk/policy/evidence/signing-keys":
                    result = repo.register_risk_policy_evidence_signing_key(body.get("key_id", ""), body.get("public_key", ""), body.get("actor", "security-admin"))
                    self._send(201, result); return
                key_revoke_match = __import__("re").fullmatch(r"/risk/policy/evidence/signing-keys/([A-Za-z0-9._-]{1,100})/revoke", path)
                if key_revoke_match:
                    result = repo.revoke_risk_policy_evidence_signing_key(key_revoke_match.group(1), body.get("actor", "security-admin"), body.get("reason", ""))
                    self._send(200, result); return
                if path == "/risk/policy/evidence":
                    result = repo.create_risk_policy_evidence(body.get("evaluation_id"), body.get("actor", "compliance-analyst"))
                    self._send(201, result); return
                if path == "/risk/policy/evidence/bundles/verify":
                    result = repo.verify_risk_policy_evidence_bundle(body.get("bundle"), body.get("signing_key"), body.get("actor", "compliance-analyst"))
                    self._send(200, result); return
                evidence_bundle_match = __import__("re").fullmatch(r"/risk/policy/evidence/([0-9]+)/bundle", path)
                if evidence_bundle_match:
                    result = repo.export_risk_policy_evidence_bundle(int(evidence_bundle_match.group(1)), body.get("signing_key"), body.get("actor", "compliance-analyst"), body.get("signing_private_key"), body.get("key_id"))
                    self._send(200, result); return
                if path == "/risk/policy/exceptions":
                    result = repo.create_risk_policy_exception(body.get("rule_id"), body.get("requested_by", "analyst"), body.get("reviewer", "reviewer"), body.get("reason", ""), body.get("expires_at", ""))
                    self._send(201, result); return
                if path == "/risk/policy/retention":
                    self._send(200, repo.set_risk_policy_retention(body.get("retention_days"), body.get("actor", "admin"))); return
                if path == "/risk/policy/retention/prune":
                    self._send(200, repo.prune_risk_policy_evaluations(body.get("actor", "retention-worker"), dry_run=body.get("dry_run", True))); return
                exception_action = __import__("re").fullmatch(r"/risk/policy/exceptions/([0-9]+)/(review|revoke)", path)
                if exception_action:
                    exception_id = int(exception_action.group(1)); action = exception_action.group(2)
                    if action == "review": result = repo.review_risk_policy_exception(exception_id, body.get("reviewer", "reviewer"), body.get("decision", ""), body.get("note", ""))
                    else: result = repo.revoke_risk_policy_exception(exception_id, body.get("actor", "admin"), body.get("reason", ""))
                    self._send(200, result); return
                if path == "/risk/policy/evaluate":
                    self._send(200, repo.evaluate_risk_intelligence_policy(body.get("actor", "policy-engine"))); return
                if path == "/risk/rules":
                    self._send(201 if not body.get("id") else 200, repo.save_risk_intelligence_rule(body))
                    return
                if path == "/risk/rules/import":
                    self._send(200, repo.import_risk_intelligence_rules(body.get("bundle", body), body.get("actor", "import"))); return
                governance_action = __import__("re").fullmatch(r"/risk/rules/([0-9]+)/(approve|unlock|active-version)", path)
                if governance_action:
                    rule_id=int(governance_action.group(1)); action=governance_action.group(2)
                    if action == "approve": result=repo.approve_risk_intelligence_rule(rule_id,body.get("actor","approver"),lock=body.get("lock",True))
                    elif action == "unlock": result=repo.unlock_risk_intelligence_rule(rule_id,body.get("actor","approver"),body.get("reason",""))
                    else: result=repo.set_risk_intelligence_active_version(rule_id,body.get("version_number"),body.get("actor","analyst"))
                    self._send(200,result); return
                rule_rollback = __import__("re").fullmatch(r"/risk/rules/([0-9]+)/rollback", path)
                if rule_rollback:
                    rule_id = int(rule_rollback.group(1))
                    if rule_id < 1: raise ValueError("Resource ID must be a positive integer")
                    version = body.get("version_number")
                    self._send(200, repo.rollback_risk_intelligence_rule(rule_id, version, body.get("actor", "analyst")))
                    return
                rule_enabled = __import__("re").fullmatch(r"/risk/rules/([0-9]+)/enabled", path)
                if rule_enabled:
                    rule_id = int(rule_enabled.group(1))
                    if rule_id < 1:
                        raise ValueError("Resource ID must be a positive integer")
                    self._send(200, repo.set_risk_intelligence_rule_enabled(rule_id, body.get("enabled"), body.get("actor", "analyst")))
                    return
                if path == "/risk/config":
                    self._send(200, repo.set_risk_intelligence_config(body))
                    return
                alert_ack = __import__("re").fullmatch(r"/risk/alerts/([0-9]+)/acknowledge", path)
                if alert_ack:
                    alert_id = int(alert_ack.group(1))
                    if alert_id < 1:
                        raise ValueError("Resource ID must be a positive integer")
                    if "acknowledged_by" in body and not isinstance(body["acknowledged_by"], str):
                        raise ValueError("acknowledged_by must be a string")
                    self._send(200, repo.acknowledge_risk_intelligence_alert(alert_id, body.get("acknowledged_by", "analyst")))
                    return
                if path == "/remediation/trend-snapshots":
                    for field in ("start_date", "end_date"):
                        if field in body and body[field] is not None and not isinstance(body[field], str):
                            raise ValueError(f"{field} must be a string date or null")
                    snapshot = repo.save_remediation_trend_snapshot(start_date=body.get("start_date"), end_date=body.get("end_date"))
                    self._send(201, snapshot)
                    return
                verification_match = __import__("re").fullmatch(r"/remediation/([0-9]+)/verification", path)
                if verification_match:
                    task_id = int(verification_match.group(1))
                    if task_id < 1:
                        raise ValueError("Resource ID must be a positive integer")
                    for field in ("outcome", "evidence", "notes", "verified_by"):
                        if field in body and not isinstance(body[field], str):
                            raise ValueError(f"{field} must be a string")
                    result = repo.record_remediation_verification(task_id, outcome=body.get("outcome", "pending"),
                        evidence=body.get("evidence", ""), notes=body.get("notes", ""), verified_by=body.get("verified_by", ""))
                    self._send(200, result)
                    return
                remediation_match = __import__("re").fullmatch(r"/findings/([0-9]+)/remediation", path)
                if verification_match:
                    pass
                elif remediation_match:
                    finding_id = int(remediation_match.group(1))
                    if finding_id < 1:
                        raise ValueError("Resource ID must be a positive integer")
                    if not any(item.id == finding_id for item in repo.list_findings()):
                        self._error(404, "Finding not found", "not_found")
                        return
                    for field in ("status", "assignee", "due_date", "notes"):
                        if field in body and body[field] is not None and not isinstance(body[field], str):
                            raise ValueError(f"{field} must be a string")
                    if body.get("status") == "resolved":
                        existing_tasks = [item for item in repo.list_remediation_tasks() if int(item["finding_id"]) == finding_id]
                        if not existing_tasks:
                            raise ValueError("A task cannot be closed before it has a recorded successful verification")
                        latest = repo.latest_remediation_verification(int(existing_tasks[0]["id"]))
                        if not latest or latest.get("outcome") != "verified":
                            raise ValueError("A task cannot be closed before it has a recorded successful verification")
                    task = repo.upsert_remediation_task(finding_id, status=body.get("status"),
                        assignee=body.get("assignee"), due_date=body.get("due_date"), notes=body.get("notes"))
                    self._send(200, task)
                else:
                    criticality_match = __import__("re").fullmatch(r"/targets/([0-9]+)/criticality", path)
                if remediation_match:
                    pass  # response was sent by the remediation handler above
                elif path == "/remediation/sla-policy":
                    severity = body.get("severity")
                    days = body.get("days")
                    if not isinstance(severity, str):
                        raise ValueError("severity must be a string")
                    if isinstance(days, bool) or not isinstance(days, int):
                        raise ValueError("days must be an integer")
                    self._send(200, {"severity": severity.title(), **repo.set_remediation_sla_policy(severity, days)})
                elif criticality_match:
                    target_id = int(criticality_match.group(1))
                    if target_id < 1:
                        raise ValueError("Resource ID must be a positive integer")
                    target = repo.set_target_criticality(target_id, body.get("criticality", ""))
                    self._send(200, asdict(target))
                elif path == "/targets":
                    if body.get("authorized") is not True:
                        self._error(403, "Set authorized=true only after confirming permission to assess this target", "authorization_confirmation_required")
                        return
                    target = repo.add_target(str(body.get("url", "")), authorized=True)
                    self._send(201, asdict(target))
                elif path == "/jobs":
                    target_url = body.get("target_url")
                    tool = body.get("tool", "demo")
                    if not isinstance(target_url, str) or not isinstance(tool, str):
                        raise ValueError("target_url and tool must be strings")
                    job = repo.create_job(target_url, tool)
                    self._send(201, asdict(job))
                else:
                    self._error(404, "Not found", "not_found")
            except PermissionError as exc:
                self._error(403, str(exc), "forbidden")
            except (ValueError, TypeError) as exc:
                self._error(400, str(exc), "invalid_request")

        def do_PUT(self) -> None:  # noqa: N802
            if self._begin_request():
                self._error(405, "Method not allowed", "method_not_allowed")

        def do_DELETE(self) -> None:  # noqa: N802
            if self._begin_request():
                self._error(405, "Method not allowed", "method_not_allowed")

    return APIHandler


def serve_api(repo: Repository, *, host: str = "127.0.0.1", port: int = 8765, token: str | None = None) -> None:
    """Serve the API on loopback only. A bearer token must be configured."""
    if host not in ALLOWED_HOSTS:
        raise ValueError("API can bind only to loopback addresses (127.0.0.1, localhost, ::1)")
    if not 0 <= port <= 65535:
        raise ValueError("port must be between 0 and 65535")
    token = token or os.environ.get("CYBERSEC_API_TOKEN")
    if not token or len(token) < 24:
        raise ValueError("Set CYBERSEC_API_TOKEN to a random secret of at least 24 characters")
    server = ThreadingHTTPServer((host, port), make_handler(repo, token))
    server.daemon_threads = True
    print(f"CyberSec local API listening on http://{host}:{server.server_port}; scanner execution is not exposed")
    try:
        server.serve_forever(poll_interval=0.25)
    except KeyboardInterrupt:
        print("Stopping local API...")
    finally:
        server.server_close()
