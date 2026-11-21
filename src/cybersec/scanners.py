"""Scanner adapter contracts and a non-networking demo adapter.

Stage 2 intentionally does not execute third-party scanners. Future adapters must
be explicitly registered and must enforce target scope, timeouts and rate limits.
"""
from __future__ import annotations

from dataclasses import dataclass, field
import ipaddress
import json
import os
import shutil
import subprocess
import time
from typing import Any, Protocol
from urllib.error import HTTPError, URLError
from urllib.parse import urlencode, urlparse, urlunparse
from urllib.request import Request, urlopen


@dataclass(frozen=True)
class ScanContext:
    job_id: int
    target_url: str
    tool: str
    options: dict[str, Any] = field(default_factory=dict)


@dataclass(frozen=True)
class ScanResult:
    tool: str
    status: str
    summary: str
    raw_output: dict[str, Any] = field(default_factory=dict)
    findings: tuple[dict[str, Any], ...] = ()


class ScannerAdapter(Protocol):
    """Common interface all scanner adapters must implement."""

    name: str

    def run(self, context: ScanContext) -> ScanResult:
        """Execute a scan and return structured output."""
        ...


class DemoAdapter:
    """Safe adapter for testing the job lifecycle; performs no network access."""

    name = "demo"

    def run(self, context: ScanContext) -> ScanResult:
        return ScanResult(
            tool=self.name,
            status="completed",
            summary=f"Dry run completed for job #{context.job_id}; no requests were sent.",
            raw_output={
                "mode": "dry-run",
                "job_id": context.job_id,
                "target_url": context.target_url,
                "network_requests": 0,
            },
        )


class AdapterRegistry:
    """Registry for adapters available to the runner."""

    def __init__(self) -> None:
        self._adapters: dict[str, ScannerAdapter] = {}

    def register(self, adapter: ScannerAdapter) -> None:
        key = adapter.name.strip().lower()
        if not key:
            raise ValueError("Adapter name cannot be empty.")
        if key in self._adapters:
            raise ValueError(f"Adapter already registered: {key}")
        self._adapters[key] = adapter

    def get(self, name: str) -> ScannerAdapter:
        try:
            return self._adapters[name.strip().lower()]
        except KeyError as exc:
            available = ", ".join(sorted(self._adapters)) or "none"
            raise LookupError(
                f"No executable adapter registered for '{name}'. Available adapters: {available}."
            ) from exc

    def names(self) -> tuple[str, ...]:
        return tuple(sorted(self._adapters))


class ZapPassiveAdapter:
    """OWASP ZAP passive-only adapter using a locally hosted ZAP API.

    It requests the target URL once through ZAP with redirects disabled, waits for
    passive analysis, then retrieves alerts. It never invokes spider, active scan,
    or any attack-oriented endpoint. ZAP's API must be bound to loopback.
    """

    name = "zap"

    def __init__(self, api_url: str | None = None, api_key: str | None = None,
                 timeout: float = 30.0, max_wait: float = 90.0, poll_interval: float = 0.5):
        self.api_url = (api_url or os.environ.get("CYBERSEC_ZAP_API_URL", "http://127.0.0.1:8080")).rstrip("/")
        self.api_key = api_key if api_key is not None else os.environ.get("CYBERSEC_ZAP_API_KEY", "")
        self.timeout = timeout
        self.max_wait = max_wait
        self.poll_interval = poll_interval
        parsed = urlparse(self.api_url)
        if parsed.scheme != "http" or not parsed.hostname:
            raise ValueError("ZAP API must use http:// on a loopback address (for example http://127.0.0.1:8080).")
        try:
            is_loopback = ipaddress.ip_address(parsed.hostname).is_loopback
        except ValueError:
            is_loopback = parsed.hostname.lower() == "localhost"
        if not is_loopback:
            raise ValueError("Refusing non-loopback ZAP API endpoint; keep the scanner API local-only.")
        if parsed.username or parsed.password:
            raise ValueError("Do not put credentials in CYBERSEC_ZAP_API_URL; use CYBERSEC_ZAP_API_KEY.")

    def _api(self, component: str, category: str, action: str, params: dict[str, Any] | None = None) -> dict[str, Any]:
        query = dict(params or {})
        if self.api_key:
            query["apikey"] = self.api_key
        url = f"{self.api_url}/JSON/{component}/{category}/{action}/?{urlencode(query)}"
        request = Request(url, headers={"Accept": "application/json", "User-Agent": "CyberSec-Orchestrator/0.3.0"})
        try:
            with urlopen(request, timeout=self.timeout) as response:
                payload = json.loads(response.read().decode("utf-8"))
        except (HTTPError, URLError, TimeoutError, OSError, json.JSONDecodeError) as exc:
            raise RuntimeError(f"ZAP API request failed ({component}/{category}/{action}): {exc}") from exc
        if not isinstance(payload, dict):
            raise RuntimeError("ZAP API returned an unexpected response format.")
        if payload.get("code") and str(payload.get("code")) not in {"ok", "0"}:
            raise RuntimeError(f"ZAP API error: {payload}")
        return payload

    @staticmethod
    def _origin(url: str) -> tuple[str, str, int]:
        parsed = urlparse(url)
        if parsed.scheme not in {"http", "https"} or not parsed.hostname or parsed.username or parsed.password:
            raise ValueError("ZAP target must be an http(s) URL without embedded credentials.")
        port = parsed.port or (443 if parsed.scheme == "https" else 80)
        return parsed.scheme.lower(), parsed.hostname.lower().rstrip("."), port

    def run(self, context: ScanContext) -> ScanResult:
        from cybersec.production_admission import require_production_admission
        require_production_admission(action="ZapPassiveAdapter.run")
        target = context.target_url
        origin = self._origin(target)
        # Keep URL paths and query but remove fragments; fragments are never sent over HTTP.
        parsed_target = urlparse(target)
        target = urlunparse((parsed_target.scheme, parsed_target.netloc, parsed_target.path or "/", "", parsed_target.query, ""))
        self._api("core", "view", "version")  # fail fast before changing target state
        self._api("core", "action", "accessUrl", {"url": target, "followRedirects": "false"})
        deadline = time.monotonic() + self.max_wait
        records_to_scan = None
        while time.monotonic() < deadline:
            response = self._api("pscan", "view", "recordsToScan")
            try:
                records_to_scan = int(response.get("recordsToScan", 0))
            except (TypeError, ValueError):
                records_to_scan = 0
            if records_to_scan <= 0:
                break
            time.sleep(self.poll_interval)
        else:
            raise TimeoutError(f"ZAP passive scan did not drain within {self.max_wait:g} seconds.")

        alerts_response = self._api("core", "view", "alerts", {"baseurl": target, "start": 0, "count": 500})
        alerts = alerts_response.get("alerts", [])
        if not isinstance(alerts, list):
            alerts = []
        findings = []
        out_of_scope = 0
        severity_map = {"3": "High", "2": "Medium", "1": "Low", "0": "Info"}
        for alert in alerts:
            if not isinstance(alert, dict):
                continue
            alert_url = str(alert.get("url", target))
            try:
                same_origin = self._origin(alert_url) == origin
            except ValueError:
                same_origin = False
            if not same_origin:
                out_of_scope += 1
                continue
            risk = str(alert.get("riskcode", "0"))
            findings.append({
                "title": str(alert.get("alert", "ZAP alert")),
                "vuln_type": str(alert.get("alert", "ZAP alert")),
                "severity": severity_map.get(risk, "Info"),
                "confidence": str(alert.get("confidence", "Unknown")),
                "url": alert_url,
                "method": str(alert.get("method", "GET")),
                "parameter": str(alert.get("param", "")) or None,
                "evidence": str(alert.get("evidence", "")),
                "description": str(alert.get("description", "")),
                "solution": str(alert.get("solution", "")),
                "source_tool": self.name,
                "plugin_id": str(alert.get("pluginId", "")),
            })
        return ScanResult(
            tool=self.name,
            status="completed",
            summary=f"ZAP passive analysis completed; {len(findings)} in-scope alert(s) collected. No active scan was run.",
            raw_output={"mode": "passive-only", "target_url": target, "alerts_received": len(alerts),
                        "alerts_in_scope": len(findings), "alerts_discarded_out_of_scope": out_of_scope,
                        "active_scan": False, "spider": False, "records_to_scan": records_to_scan},
            findings=tuple(findings),
        )



class NucleiAdapter:
    """Run Nuclei with conservative, fixed options against an authorized target.

    The adapter intentionally does not accept arbitrary CLI arguments or template paths.
    It limits execution to low-impact technology, exposure, TLS and misconfiguration tags,
    disables update checks, caps request rate/concurrency, and discards results outside
    the registered target origin.
    """

    name = "nuclei"

    def __init__(self, executable: str | None = None, timeout: float = 300.0,
                 rate_limit: int = 5, concurrency: int = 2):
        self.executable = executable or os.environ.get("CYBERSEC_NUCLEI_PATH") or shutil.which("nuclei")
        self.timeout = timeout
        self.rate_limit = rate_limit
        self.concurrency = concurrency
        if timeout <= 0 or timeout > 1800:
            raise ValueError("Nuclei timeout must be greater than 0 and at most 1800 seconds.")
        if not 1 <= rate_limit <= 10:
            raise ValueError("Nuclei rate_limit must be between 1 and 10 requests per second.")
        if not 1 <= concurrency <= 4:
            raise ValueError("Nuclei concurrency must be between 1 and 4.")

    @staticmethod
    def _origin(url: str) -> tuple[str, str, int]:
        parsed = urlparse(url)
        if parsed.scheme not in {"http", "https"} or not parsed.hostname or parsed.username or parsed.password:
            raise ValueError("Nuclei target/result must be an http(s) URL without embedded credentials.")
        try:
            port = parsed.port or (443 if parsed.scheme.lower() == "https" else 80)
        except ValueError as exc:
            raise ValueError("Nuclei URL has an invalid port.") from exc
        return parsed.scheme.lower(), parsed.hostname.lower().rstrip("."), port

    def run(self, context: ScanContext) -> ScanResult:
        from cybersec.production_admission import require_production_admission
        require_production_admission(action="NucleiAdapter.run")
        if not self.executable:
            raise RuntimeError("Nuclei executable not found. Install Nuclei or set CYBERSEC_NUCLEI_PATH.")
        target = context.target_url
        target_origin = self._origin(target)
        command = [
            self.executable, "-u", target, "-jsonl", "-silent", "-no-color",
            "-disable-update-check", "-disable-redirects", "-rate-limit", str(self.rate_limit),
            "-concurrency", str(self.concurrency), "-timeout", "5", "-retries", "0",
            "-tags", "misconfig,exposure,ssl,tech",
            "-severity", "info,low,medium,high,critical",
        ]
        try:
            interruption = context.options.get("_worker_interrupted")
            if interruption is not None and not callable(interruption):
                raise TypeError("worker interruption callback must be callable")
            # Worker-owned scans MUST use process-group supervision; fail closed
            # if POSIX process-group control is unavailable. Direct CLI retains
            # its Stage 62 opt-in for backward compatibility.
            if interruption is not None or os.environ.get("CYBERSEC_PROCESS_SUPERVISION") == "1":
                from cybersec.process_supervisor import ProcessSupervisor
                completed = ProcessSupervisor().run(command, timeout=self.timeout,
                                                    cancelled=interruption)
            else:
                completed = subprocess.run(
                    command, capture_output=True, text=True, timeout=self.timeout,
                    check=False, shell=False,
                )
        except subprocess.TimeoutExpired as exc:
            raise TimeoutError(f"Nuclei exceeded the {self.timeout:g}-second job timeout.") from exc
        except OSError as exc:
            raise RuntimeError(f"Could not start Nuclei: {exc}") from exc

        stdout = completed.stdout or ""
        stderr = (completed.stderr or "")[-4000:]
        if completed.returncode != 0:
            raise RuntimeError(f"Nuclei exited with code {completed.returncode}: {stderr.strip() or 'no error output'}")

        findings: list[dict[str, Any]] = []
        discarded = 0
        malformed = 0
        severity_map = {"critical": "Critical", "high": "High", "medium": "Medium", "low": "Low", "info": "Info"}
        for line in stdout.splitlines():
            if not line.strip():
                continue
            try:
                item = json.loads(line)
            except json.JSONDecodeError:
                malformed += 1
                continue
            if not isinstance(item, dict):
                malformed += 1
                continue
            matched_at = str(item.get("matched-at") or item.get("url") or target)
            try:
                in_scope = self._origin(matched_at) == target_origin
            except ValueError:
                in_scope = False
            if not in_scope:
                discarded += 1
                continue
            info = item.get("info") if isinstance(item.get("info"), dict) else {}
            classification = info.get("classification") if isinstance(info.get("classification"), dict) else {}
            extracted = item.get("extracted-results")
            evidence = "; ".join(str(v) for v in extracted[:5]) if isinstance(extracted, list) else ""
            findings.append({
                "title": str(info.get("name") or item.get("template-id") or "Nuclei finding"),
                "vuln_type": str(info.get("name") or item.get("info", {}).get("classification", {}).get("cwe-id") or item.get("template-id") or "Nuclei finding"),
                "severity": severity_map.get(str(info.get("severity", "info")).lower(), "Info"),
                "confidence": "Tentative",
                "url": matched_at,
                "method": str(item.get("matcher-status", "match")),
                "parameter": None,
                "evidence": evidence[:2000],
                "description": str(info.get("description", ""))[:4000],
                "solution": str(info.get("remediation", ""))[:4000],
                "source_tool": self.name,
                "template_id": str(item.get("template-id", "")),
                "matched_at": matched_at,
                "reference": info.get("reference", []),
                "cve_ids": classification.get("cve-id", []),
            })
        return ScanResult(
            tool=self.name, status="completed",
            summary=f"Nuclei completed with conservative templates; {len(findings)} in-scope finding(s) collected.",
            raw_output={"mode": "conservative-template-scan", "target_url": target,
                        "return_code": completed.returncode, "findings_received": len(stdout.splitlines()),
                        "findings_in_scope": len(findings), "findings_discarded_out_of_scope": discarded,
                        "malformed_lines": malformed, "rate_limit": self.rate_limit,
                        "concurrency": self.concurrency, "timeout_seconds": self.timeout,
                        "template_tags": ["misconfig", "exposure", "ssl", "tech"],
                        "stderr_tail": stderr},
            findings=tuple(findings),
        )



class SqlmapConfirmationAdapter:
    """Explicit, bounded SQLi confirmation; never an exploratory scan.

    This adapter is intentionally NOT in default_registry: a normal queued job
    has no candidate provenance and must never start sqlmap automatically.
    The caller must supply a previously recorded candidate and authorization.
    """

    name = "sqlmap"

    def __init__(self, executable: str | None = None, timeout: float = 90.0):
        self.executable = executable or os.environ.get("CYBERSEC_SQLMAP_PATH") or shutil.which("sqlmap")
        if not 1 <= timeout <= 120:
            raise ValueError("sqlmap timeout must be between 1 and 120 seconds")
        self.timeout = timeout

    def run(self, context: ScanContext) -> ScanResult:
        from cybersec.production_admission import require_production_admission
        require_production_admission(action="SqlmapConfirmationAdapter.run")
        from urllib.parse import parse_qs
        import re

        opts = context.options
        if opts.get("authorized") is not True or opts.get("candidate_recorded") is not True:
            raise PermissionError("Explicit current authorization and recorded candidate required")
        candidate = opts.get("candidate_url")
        parameter = opts.get("parameter")
        if not isinstance(candidate, str) or not isinstance(parameter, str):
            raise ValueError("Candidate URL and parameter are required")
        if not re.fullmatch(r"[A-Za-z_][A-Za-z0-9_.-]{0,63}", parameter):
            raise ValueError("Invalid candidate parameter")
        base = urlparse(context.target_url)
        parsed = urlparse(candidate)
        if (base.scheme not in ("http", "https") or parsed.scheme != base.scheme
                or not base.hostname or parsed.hostname != base.hostname
                or base.port != parsed.port or parsed.username or parsed.password
                or parsed.fragment or not parsed.path.startswith(base.path.rstrip("/") + "/")
                and parsed.path != base.path):
            raise ValueError("Candidate outside exact registered target scope")
        if parameter not in parse_qs(parsed.query, keep_blank_values=True):
            raise ValueError("Candidate parameter not present in query string")
        if not self.executable:
            raise RuntimeError("sqlmap executable unavailable")
        # No arbitrary options, no redirects, no enumeration, extraction or OS commands.
        argv = [self.executable, "-u", candidate, "-p", parameter,
                "--batch", "--level=1", "--risk=1", "--threads=1",
                "--timeout=5", "--retries=0", "--delay=1", "--technique=BE",
                "--smart", "--disable-coloring", "--output-dir=/tmp/cybersec-sqlmap",
                "--fresh-queries", "--ignore-redirects"]
        try:
            interruption = context.options.get("_worker_interrupted")
            if interruption is not None and not callable(interruption):
                raise TypeError("worker interruption callback must be callable")
            if interruption is not None or os.environ.get("CYBERSEC_PROCESS_SUPERVISION") == "1":
                from cybersec.process_supervisor import ProcessSupervisor
                proc = ProcessSupervisor().run(argv, timeout=self.timeout,
                                               cancelled=interruption)
            else:
                proc = subprocess.run(argv, capture_output=True, text=True,
                                      timeout=self.timeout, check=False, shell=False)
        except subprocess.TimeoutExpired as exc:
            raise TimeoutError("sqlmap confirmation exceeded bounded timeout") from exc
        if proc.returncode != 0:
            raise RuntimeError(f"sqlmap confirmation failed with exit code {proc.returncode}")
        output = (proc.stdout or "")[-16000:]
        confirmed = bool(re.search(r"Parameter:\s*" + re.escape(parameter)
                                   + r"\s*\(GET\).*?Type:\s*(?:boolean-based blind|error-based)",
                                   output, flags=re.I | re.S))
        return ScanResult(
            tool=self.name, status="completed",
            summary="SQL injection confirmed" if confirmed else "SQL injection not confirmed (inconclusive)",
            raw_output={"mode": "bounded-candidate-confirmation", "target_url": candidate,
                        "parameter": parameter, "confirmed": confirmed,
                        "timeout_seconds": self.timeout, "return_code": proc.returncode,
                        "output_sha256": __import__("hashlib").sha256(output.encode()).hexdigest(),
                        "stdout_excerpt": output[:1000]},
            findings=({"title": "SQL injection confirmation", "vuln_type": "SQL Injection",
                       "severity": "High", "confidence": "Firm", "url": candidate,
                       "parameter": parameter, "source_tool": "sqlmap",
                       "evidence": "Bounded boolean/error-based confirmation"},) if confirmed else (),
        )

def default_registry() -> AdapterRegistry:
    registry = AdapterRegistry()
    registry.register(DemoAdapter())
    registry.register(ZapPassiveAdapter())
    registry.register(NucleiAdapter())
    return registry
