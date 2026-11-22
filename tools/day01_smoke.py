#!/usr/bin/env python3
"""Stage70 Day01: isolated, non-scanning, end-to-end product smoke.
DO NOT use this as scanner evidence or production admission.
"""
from __future__ import annotations

import argparse
from contextlib import closing
import hashlib
import json
import os
from pathlib import Path
import re
import secrets
import signal
import socket
import sqlite3
import subprocess
import sys
import time
from urllib.error import HTTPError, URLError
from urllib.request import Request, build_opener, ProxyHandler

TARGET = "http://127.0.0.1:8765/"
DENIED_MODES = {"production", "prod"}
TIMEOUT = 30


def guard_environment() -> None:
    for name in ("CYBERSEC_EXECUTION_MODE", "CYBERSEC_RUNTIME_MODE"):
        if os.environ.get(name, "").strip().lower() in DENIED_MODES:
            raise RuntimeError("FAIL_CLOSED_PRODUCTION_MODE_" + name)
    if os.geteuid() == 0 and os.environ.get("CYBERSEC_DAY01_ALLOW_ROOT_CI") != "1":
        raise RuntimeError("REFUSE_ROOT_EXECUTION: run demo as an unprivileged user")


def digest(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def run_cli(args: list[str], *, env: dict[str, str], events: list[dict], timeout: int = TIMEOUT) -> str:
    cmd = [sys.executable, "-m", "cybersec", *args]
    started = time.monotonic()
    result = subprocess.run(cmd, capture_output=True, text=True, env=env, timeout=timeout, check=False)
    events.append({"command": cmd[1:], "exit_code": result.returncode,
                   "duration_seconds": round(time.monotonic()-started, 3),
                   "stdout": result.stdout[-10000:], "stderr": result.stderr[-10000:]})
    if result.returncode:
        raise RuntimeError("CLI_FAILED_" + " ".join(args) + ": " + result.stderr[-700:])
    return result.stdout


def http_get(url: str, token: str | None = None) -> tuple[int, bytes]:
    headers = {"Accept": "application/json"}
    if token is not None:
        headers["Authorization"] = "Bearer " + token
    opener = build_opener(ProxyHandler({}))
    try:
        with opener.open(Request(url, headers=headers), timeout=1.5) as response:
            return response.status, response.read(200000)
    except HTTPError as exc:
        return exc.code, exc.read(20000)


def available_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.bind(("127.0.0.1", 0))
        return sock.getsockname()[1]


def verify_api(*, env: dict[str, str], events: list[dict]) -> None:
    port = available_port()
    token = secrets.token_urlsafe(36)
    child_env = dict(env, CYBERSEC_API_TOKEN=token)
    proc = subprocess.Popen([sys.executable, "-m", "cybersec", "api", "serve",
                             "--host", "127.0.0.1", "--port", str(port)],
                            stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                            stderr=subprocess.PIPE, text=True, env=child_env)
    base = "http://127.0.0.1:" + str(port)
    try:
        deadline = time.monotonic() + 12
        while time.monotonic() < deadline:
            if proc.poll() is not None:
                raise RuntimeError("API_EXITED_EARLY_" + str(proc.returncode))
            try:
                status, health = http_get(base + "/health")
                if status == 200:
                    break
            except (OSError, URLError):
                pass
            time.sleep(0.15)
        else:
            raise TimeoutError("API_START_TIMEOUT")
        if json.loads(health).get("ok") is not True:
            raise AssertionError("HEALTH_NOT_OK")
        dashboard_code, page = http_get(base + "/dashboard")
        if dashboard_code != 200 or b"<html" not in page.lower():
            raise AssertionError("DASHBOARD_UNAVAILABLE")
        unauth_code, _ = http_get(base + "/api/v1/targets")
        if unauth_code != 401:
            raise AssertionError("API_UNAUTHENTICATED_REQUEST_NOT_DENIED")
        auth_code, payload = http_get(base + "/api/v1/targets", token=token)
        if auth_code != 200:
            raise AssertionError("API_AUTHENTICATED_REQUEST_FAILED")
        if not isinstance(json.loads(payload), (dict, list)):
            raise AssertionError("API_JSON_INVALID")
        events.append({"check": "loopback_api_dashboard_auth", "health": status,
                       "dashboard": dashboard_code, "unauthorized": unauth_code,
                       "authorized": auth_code, "passed": True,
                       "token_logged": False})
    finally:
        if proc.poll() is None:
            proc.terminate()
        try:
            stdout, stderr = proc.communicate(timeout=5)
        except subprocess.TimeoutExpired:
            proc.kill()
            stdout, stderr = proc.communicate(timeout=3)
        events.append({"check": "api_shutdown", "exit_code": proc.returncode,
                       "stdout": stdout[-3000:], "stderr": stderr[-3000:]})


def smoke(evidence_dir: Path, *, font_path: str | None) -> dict:
    guard_environment()
    evidence_dir = evidence_dir.resolve()
    evidence_dir.mkdir(parents=True, exist_ok=False)
    state_dir = evidence_dir / "state"
    state_dir.mkdir(mode=0o700)
    env = os.environ.copy()
    env.update(CYBERSEC_HOME=str(state_dir),
               CYBERSEC_EXECUTION_MODE="demo",
               CYBERSEC_RUNTIME_MODE="demo")
    events: list[dict] = []
    result: dict = {"schema": "stage70-day01-smoke-v1", "mode": "OFFLINE_DEMO_NOT_A_SECURITY_SCAN",
                    "production_admission": "BLOCKED_NO_GO", "events": events,
                    "pass": False, "target": TARGET, "scanner_network_requests": 0}
    try:
        run_cli(["init"], env=env, events=events)
        run_cli(["target", "add", TARGET, "--authorized"], env=env, events=events)
        created = run_cli(["job", "create", TARGET, "--tool", "demo"], env=env, events=events)
        match = re.search(r"Created queued job #(\d+)", created)
        if not match:
            raise AssertionError("JOB_ID_MISSING")
        job_id = match.group(1)
        output = run_cli(["job", "run", job_id], env=env, events=events)
        if "network_requests" not in output or '"network_requests": 0' not in output:
            raise AssertionError("DEMO_NETWORK_REQUESTS_NOT_ZERO")
        run_cli(["finding", "add", TARGET, "--title", "Synthetic evidence only",
                 "--severity", "Low", "--type", "demo-only",
                 "--evidence", "Synthetic demo. No vulnerability observed."],
                env=env, events=events)
        jobs = run_cli(["job", "list"], env=env, events=events)
        if "completed" not in jobs:
            raise AssertionError("JOB_NOT_COMPLETED")
        html = evidence_dir / "report.html"
        pdf = evidence_dir / "report.pdf"
        run_cli(["report", "html", "--output", str(html)], env=env, events=events)
        pdf_args = ["report", "pdf", "--output", str(pdf)]
        if font_path:
            pdf_args += ["--font-path", font_path]
        run_cli(pdf_args, env=env, events=events)
        if b"Synthetic evidence only" not in html.read_bytes():
            raise AssertionError("HTML_FINDING_NOT_PRESENT")
        if pdf.read_bytes()[:5] != b"%PDF-":
            raise AssertionError("PDF_HEADER_INVALID")
        db = state_dir / "cybersec.db"
        with closing(sqlite3.connect(db)) as conn:
            target_count = conn.execute("select count(*) from targets").fetchone()[0]
            completed = conn.execute("select count(*) from scan_jobs where tool='demo' and status='completed'").fetchone()[0]
            finding_count = conn.execute("select count(*) from normalized_findings where source_tool='manual'").fetchone()[0]
            artifacts = conn.execute("select count(*) from scan_artifacts").fetchone()[0]
        if (target_count, completed, finding_count, artifacts) != (1, 1, 1, 1):
            raise AssertionError("DB_E2E_MISMATCH:" + str((target_count, completed, finding_count, artifacts)))
        events.append({"check": "sqlite_e2e_counts", "targets": target_count,
                       "completed_demo_jobs": completed, "synthetic_findings": finding_count,
                       "demo_raw_artifacts": artifacts, "passed": True})
        verify_api(env=env, events=events)
        result.update({"pass": True, "checks": 8,
                       "artifacts": {p.name: {"sha256": digest(p), "size": p.stat().st_size}
                                     for p in (html, pdf, db)}})
        return result
    finally:
        (evidence_dir / "smoke_result.json").write_text(json.dumps(result, indent=2, sort_keys=True) + "\n")


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--evidence-dir", type=Path, required=True)
    parser.add_argument("--font-path", default=None, help="locally installed Unicode TTF; never bundled")
    args = parser.parse_args(argv)
    try:
        report = smoke(args.evidence_dir, font_path=args.font_path)
        print("DAY01_SMOKE_PASS: CLI, SQLite, offline demo, HTML, PDF, API and dashboard")
        print(json.dumps({k: v for k, v in report.items() if k != "events"}, sort_keys=True))
        return 0
    except Exception as exc:
        print("DAY01_SMOKE_FAIL: " + type(exc).__name__ + ": " + str(exc), file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
