"""Local alert policies and a durable notification queue (no delivery integrations)."""
from __future__ import annotations

import json
from typing import Iterable

from cybersec.db import connect

SEVERITIES = {"Critical", "High", "Medium", "Low", "Info"}
EVENT_TYPES = {"added", "reappeared", "changed"}


def add_policy(repo, name: str, severities: Iterable[str] = ("Critical", "High"),
               event_types: Iterable[str] = ("added", "reappeared", "changed"),
               enabled: bool = True) -> dict:
    name = name.strip()
    severities = sorted(set(severities))
    event_types = sorted(set(event_types))
    if not name:
        raise ValueError("Policy name cannot be empty.")
    if not severities or not set(severities) <= SEVERITIES:
        raise ValueError("Select one or more valid severities: Critical, High, Medium, Low, Info.")
    if not event_types or not set(event_types) <= EVENT_TYPES:
        raise ValueError("Select one or more valid event types: added, reappeared, changed.")
    with connect(repo.db_path) as db:
        db.execute("INSERT INTO alert_policies(name,severities_json,event_types_json,enabled) VALUES(?,?,?,?) "
                   "ON CONFLICT(name) DO UPDATE SET severities_json=excluded.severities_json, "
                   "event_types_json=excluded.event_types_json, enabled=excluded.enabled",
                   (name, json.dumps(severities), json.dumps(event_types), int(enabled)))
        row = db.execute("SELECT * FROM alert_policies WHERE name=?", (name,)).fetchone()
    return _policy(row)


def _policy(row) -> dict:
    return {"id": row["id"], "name": row["name"],
            "severities": json.loads(row["severities_json"]),
            "event_types": json.loads(row["event_types_json"]),
            "enabled": bool(row["enabled"]), "created_at": row["created_at"]}


def list_policies(repo) -> list[dict]:
    with connect(repo.db_path) as db:
        rows = db.execute("SELECT * FROM alert_policies ORDER BY id").fetchall()
    return [_policy(row) for row in rows]


def _events_for_comparison(result: dict) -> list[dict]:
    events: list[dict] = []
    for event_type in ("added", "reappeared", "changed"):
        records = result.get(event_type, [])
        if not isinstance(records, list):
            continue
        for record in records:
            if not isinstance(record, dict):
                continue
            if event_type == "changed":
                before, after = record.get("before", {}), record.get("after", {})
                finding = after if isinstance(after, dict) else {}
                severity = finding.get("severity", "Info")
                title = finding.get("title", "Finding severity changed")
                identity = finding.get("identity", "")
                details = {"before": before, "after": after}
            else:
                finding = record
                severity = finding.get("severity", "Info")
                title = finding.get("title", "Untitled finding")
                identity = finding.get("identity", "")
                details = finding
            if severity not in SEVERITIES:
                severity = "Info"
            events.append({"event_type": event_type, "severity": severity,
                           "finding_identity": str(identity), "title": str(title),
                           "details": details})
    # A finding may already be classified as reappeared by upstream analytics; avoid duplicate added event.
    unique = {}
    for event in events:
        key = (event["event_type"], event["finding_identity"], event["severity"])
        unique[key] = event
    return list(unique.values())


def evaluate_comparison(repo, comparison_id: int) -> dict:
    comparison = repo.get_comparison(comparison_id)
    if comparison is None:
        raise ValueError(f"Comparison history #{comparison_id} does not exist.")
    result = comparison.get("result", {})
    events = _events_for_comparison(result)
    policies = [p for p in list_policies(repo) if p["enabled"]]
    queued = 0
    with connect(repo.db_path) as db:
        for policy in policies:
            for event in events:
                if event["severity"] not in policy["severities"] or event["event_type"] not in policy["event_types"]:
                    continue
                event_key = f"comparison:{comparison_id}|policy:{policy['id']}|type:{event['event_type']}|identity:{event['finding_identity']}|severity:{event['severity']}"
                cursor = db.execute(
                    "INSERT OR IGNORE INTO notification_events(policy_id,comparison_id,event_key,event_type,severity,title,payload_json,status) "
                    "VALUES(?,?,?,?,?,?,?,'pending')",
                    (policy["id"], comparison_id, event_key, event["event_type"], event["severity"], event["title"],
                     json.dumps(event["details"], ensure_ascii=False, sort_keys=True)))
                queued += cursor.rowcount
        pending = db.execute("SELECT COUNT(*) FROM notification_events WHERE status='pending'").fetchone()[0]
    return {"comparison_id": comparison_id, "candidate_events": len(events),
            "newly_queued": queued, "pending_total": pending,
            "delivery": "disabled; events are stored locally only"}


def list_events(repo, status: str | None = None, limit: int = 100) -> list[dict]:
    if limit < 1 or limit > 1000:
        raise ValueError("Event limit must be between 1 and 1000.")
    if status is not None and status not in {"pending", "acknowledged", "suppressed"}:
        raise ValueError("Status must be pending, acknowledged, or suppressed.")
    sql = "SELECT * FROM notification_events"
    params: list[object] = []
    if status:
        sql += " WHERE status=?"; params.append(status)
    sql += " ORDER BY id DESC LIMIT ?"; params.append(limit)
    with connect(repo.db_path) as db:
        rows = db.execute(sql, params).fetchall()
    result = []
    for row in rows:
        item = dict(row)
        item["payload"] = json.loads(item.pop("payload_json"))
        result.append(item)
    return result


def update_event_status(repo, event_id: int, status: str) -> dict:
    if status not in {"acknowledged", "suppressed"}:
        raise ValueError("Status must be acknowledged or suppressed.")
    with connect(repo.db_path) as db:
        cursor = db.execute("UPDATE notification_events SET status=?, updated_at=strftime('%Y-%m-%dT%H:%M:%fZ','now') WHERE id=?",
                            (status, event_id))
        if cursor.rowcount != 1:
            raise ValueError(f"Notification event #{event_id} does not exist.")
        row = db.execute("SELECT * FROM notification_events WHERE id=?", (event_id,)).fetchone()
    item = dict(row); item["payload"] = json.loads(item.pop("payload_json"))
    return item

# Webhook delivery is deliberately opt-in and requires an explicit CLI confirmation.
# Payloads are sent only to an HTTPS URL supplied via CYBERSEC_WEBHOOK_URL.
import os
import time
import hashlib
import re
from urllib.error import HTTPError, URLError
from urllib.parse import urlsplit
from urllib.request import Request, build_opener, HTTPRedirectHandler


class _NoRedirect(HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


_SENSITIVE_KEY = re.compile(r"(password|passwd|secret|token|authorization|api[_-]?key|credential|cookie|private[_-]?key)", re.I)
_MASK = "[REDACTED]"


def mask_sensitive(value):
    """Return a sanitized copy; never mutate the stored source event."""
    if isinstance(value, dict):
        result = {}
        for key, item in value.items():
            result[str(key)] = _MASK if _SENSITIVE_KEY.search(str(key)) else mask_sensitive(item)
        return result
    if isinstance(value, list):
        return [mask_sensitive(item) for item in value]
    if isinstance(value, str):
        # Redact common inline credentials in free text without trying to parse arbitrary formats.
        value = re.sub(r"(?i)\bBearer\s+[A-Za-z0-9._~+/=-]+", "Bearer [REDACTED]", value)
        value = re.sub(r"(?i)(api[_-]?key|access[_-]?token|password|secret)=([^&\s]+)", r"\1=[REDACTED]", value)
    return value


def check_delivery_config() -> dict:
    """Validate delivery configuration locally; does not resolve DNS or contact the endpoint."""
    destination = os.environ.get("CYBERSEC_WEBHOOK_URL", "").strip()
    allowed = [host.strip().lower() for host in os.environ.get("CYBERSEC_WEBHOOK_ALLOWED_HOSTS", "").split(",") if host.strip()]
    if not destination:
        return {"valid": False, "configured": False, "reason": "CYBERSEC_WEBHOOK_URL is not configured", "allowed_hosts_configured": bool(allowed)}
    parsed = urlsplit(destination)
    valid = parsed.scheme == "https" and bool(parsed.hostname) and not parsed.username and not parsed.password and not parsed.fragment
    reason = None if valid else "URL must be HTTPS, include a hostname, contain no embedded credentials, and have no fragment"
    if valid and allowed and parsed.hostname.lower() not in allowed:
        valid = False
        reason = "Webhook hostname is not in the configured allowlist (CYBERSEC_WEBHOOK_ALLOWED_HOSTS)"
    return {"valid": valid, "configured": True, "scheme": parsed.scheme or None,
            "hostname": parsed.hostname, "allowed_hosts_configured": bool(allowed), "reason": reason}


def retry_failed_delivery(repo, event_id: int, *, confirmed: bool = False, opener=None) -> dict:
    """Retry an event only when a previous delivery failed; confirmation is still required."""
    attempts = [item for item in list_deliveries_for_event(repo, event_id)]
    if not attempts or attempts[-1]["outcome"] != "failed":
        raise ValueError("Retry is allowed only when the latest delivery attempt failed.")
    return deliver_event(repo, event_id, confirmed=confirmed, opener=opener)


def list_deliveries_for_event(repo, event_id: int) -> list[dict]:
    with connect(repo.db_path) as db:
        rows = db.execute("SELECT * FROM notification_deliveries WHERE event_id=? ORDER BY id", (event_id,)).fetchall()
    return [dict(row) for row in rows]


def preview_event(repo, event_id: int) -> dict:
    with connect(repo.db_path) as db:
        row = db.execute("SELECT * FROM notification_events WHERE id=?", (event_id,)).fetchone()
    if row is None:
        raise ValueError(f"Notification event #{event_id} does not exist.")
    return {
        "event_id": row["id"], "status": row["status"], "event_type": row["event_type"],
        "severity": row["severity"], "title": row["title"],
        "payload": mask_sensitive(json.loads(row["payload_json"])),
        "delivery_requires": ["CYBERSEC_WEBHOOK_URL configured as HTTPS", "explicit --confirm flag"],
    }


def list_deliveries(repo, limit: int = 100) -> list[dict]:
    if limit < 1 or limit > 1000:
        raise ValueError("Delivery limit must be between 1 and 1000.")
    with connect(repo.db_path) as db:
        rows = db.execute("SELECT * FROM notification_deliveries ORDER BY id DESC LIMIT ?", (limit,)).fetchall()
    return [dict(row) for row in rows]


def deliver_event(repo, event_id: int, *, confirmed: bool = False, timeout: float = 5.0,
                  retries: int = 2, opener=None) -> dict:
    """Deliver a single queued event; no delivery occurs without explicit confirmation."""
    event = preview_event(repo, event_id)
    destination = os.environ.get("CYBERSEC_WEBHOOK_URL", "").strip()
    if not confirmed:
        raise PermissionError("External delivery requires explicit --confirm. Preview the event first.")
    if event["status"] != "pending":
        raise ValueError("Only pending events can be delivered; review or re-queue the event explicitly.")
    config = check_delivery_config()
    if not config["valid"]:
        raise ValueError(config.get("reason") or "CYBERSEC_WEBHOOK_URL must be a valid HTTPS URL.")
    parsed = urlsplit(destination)
    allowed_hosts = [host.strip().lower() for host in os.environ.get("CYBERSEC_WEBHOOK_ALLOWED_HOSTS", "").split(",") if host.strip()]
    if allowed_hosts and parsed.hostname.lower() not in allowed_hosts:
        raise ValueError("Webhook hostname is not in the configured allowlist (CYBERSEC_WEBHOOK_ALLOWED_HOSTS).")
    if timeout <= 0 or timeout > 30:
        raise ValueError("Timeout must be greater than 0 and at most 30 seconds.")
    if retries < 0 or retries > 3:
        raise ValueError("Retries must be between 0 and 3.")
    safe_event = mask_sensitive(event)
    payload = json.dumps({"source": "cybersec-orchestrator", "event": safe_event}, ensure_ascii=False, sort_keys=True).encode("utf-8")
    idempotency_key = hashlib.sha256((str(event_id) + "|" + parsed.hostname.lower() + "|" + parsed.path + "|" + payload.decode("utf-8")).encode("utf-8")).hexdigest()
    request = Request(destination, data=payload, headers={"Content-Type": "application/json", "User-Agent": "cybersec-orchestrator/1.9", "Idempotency-Key": idempotency_key}, method="POST")
    client = opener or build_opener(_NoRedirect())
    status_code = None
    error_text = None
    attempts = 0
    outcome = "failed"
    for attempt in range(retries + 1):
        attempts += 1
        try:
            response = client.open(request, timeout=timeout)
            status_code = getattr(response, "status", response.getcode())
            # Read a small amount only; never persist remote response bodies.
            response.read(1024)
            if 200 <= status_code < 300:
                outcome = "sent"
                break
            error_text = f"Unexpected HTTP status {status_code}"
        except HTTPError as exc:
            status_code = exc.code
            error_text = f"HTTP status {exc.code}"
            if 300 <= exc.code < 400:
                error_text = "Redirect refused; configure the final HTTPS endpoint directly"
                break
            if exc.code < 500 and exc.code != 429:
                break
        except (URLError, TimeoutError, OSError) as exc:
            error_text = type(exc).__name__
        if attempt < retries:
            time.sleep(min(0.1 * (attempt + 1), 0.3))
    with connect(repo.db_path) as db:
        db.execute("INSERT INTO notification_deliveries(event_id,destination_host,outcome,http_status,attempt_count,error,idempotency_key) VALUES(?,?,?,?,?,?,?)",
                   (event_id, parsed.hostname or "unknown", outcome, status_code, attempts, error_text, idempotency_key))
        if outcome == "sent":
            db.execute("UPDATE notification_events SET status='acknowledged', updated_at=strftime('%Y-%m-%dT%H:%M:%fZ','now') WHERE id=? AND status='pending'", (event_id,))
    return {"event_id": event_id, "outcome": outcome, "destination_host": parsed.hostname,
            "http_status": status_code, "attempt_count": attempts, "error": error_text,
            "note": "Delivery response body is not retained."}
