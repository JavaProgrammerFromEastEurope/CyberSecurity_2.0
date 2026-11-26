"""Durable, lease-based notification queue helpers for concurrent workers."""
from __future__ import annotations

import json
import os
import socket
import uuid
from datetime import datetime, timedelta, timezone

from cybersec.db import connect


def _now() -> datetime:
    return datetime.now(timezone.utc)


def _iso(value: datetime) -> str:
    return value.isoformat(timespec="milliseconds").replace("+00:00", "Z")


def queue_stats(repo) -> dict:
    now = _iso(_now())
    with connect(repo.db_path) as db:
        counts = {row["status"]: row["count"] for row in db.execute(
            "SELECT status, COUNT(*) AS count FROM notification_events GROUP BY status").fetchall()}
        due = db.execute("SELECT COUNT(*) FROM notification_events e WHERE e.status='pending' AND (e.next_attempt_at IS NULL OR e.next_attempt_at<=?) AND (e.lease_until IS NULL OR e.lease_until<=?) AND NOT EXISTS (SELECT 1 FROM notification_dead_letters d WHERE d.event_id=e.id AND d.resolved_at IS NULL)", (now, now)).fetchone()[0]
        leased = db.execute("SELECT COUNT(*) FROM notification_events e WHERE e.status='pending' AND e.lease_until>? AND NOT EXISTS (SELECT 1 FROM notification_dead_letters d WHERE d.event_id=e.id AND d.resolved_at IS NULL)", (now,)).fetchone()[0]
        delayed = db.execute("SELECT COUNT(*) FROM notification_events e WHERE e.status='pending' AND e.next_attempt_at>? AND NOT EXISTS (SELECT 1 FROM notification_dead_letters d WHERE d.event_id=e.id AND d.resolved_at IS NULL)", (now,)).fetchone()[0]
        quarantined = db.execute("SELECT COUNT(*) FROM notification_dead_letters WHERE resolved_at IS NULL").fetchone()[0]
    return {"by_status": {key: counts.get(key, 0) for key in ("pending", "acknowledged", "suppressed")},
            "due_pending": due, "leased": leased, "delayed": delayed, "quarantined": quarantined}


def claim_next(repo, worker_id: str | None = None, lease_seconds: int = 60) -> dict | None:
    """Atomically claim one due event. Expired leases are reclaimable after worker crashes."""
    if lease_seconds < 5 or lease_seconds > 3600:
        raise ValueError("Lease duration must be between 5 and 3600 seconds.")
    if worker_id is None:
        worker_id = f"{socket.gethostname()}-{os.getpid()}-{uuid.uuid4().hex[:8]}"
    worker_id = worker_id.strip()
    if not worker_id or len(worker_id) > 128:
        raise ValueError("Worker ID must be 1-128 characters.")
    now = _now(); now_text = _iso(now); until_text = _iso(now + timedelta(seconds=lease_seconds))
    with connect(repo.db_path) as db:
        db.execute("BEGIN IMMEDIATE")
        row = db.execute("SELECT e.id FROM notification_events e WHERE e.status='pending' AND (e.next_attempt_at IS NULL OR e.next_attempt_at<=?) AND (e.lease_until IS NULL OR e.lease_until<=?) AND NOT EXISTS (SELECT 1 FROM notification_dead_letters d WHERE d.event_id=e.id AND d.resolved_at IS NULL) ORDER BY e.id LIMIT 1", (now_text, now_text)).fetchone()
        if row is None:
            return None
        event_id = row["id"]
        changed = db.execute("UPDATE notification_events SET lease_owner=?, lease_until=? WHERE id=? AND status='pending' AND (lease_until IS NULL OR lease_until<=?)", (worker_id, until_text, event_id, now_text)).rowcount
        if changed != 1:
            return None
        event = db.execute("SELECT * FROM notification_events WHERE id=?", (event_id,)).fetchone()
    item = dict(event)
    item["payload"] = json.loads(item.pop("payload_json"))
    return item


def finish_claim(repo, event_id: int, worker_id: str, *, outcome: str, error: str | None = None,
                 base_delay_seconds: int = 30, max_delay_seconds: int = 3600,
                 max_attempts: int = 5) -> dict:
    """Release a worker lease and schedule a bounded exponential retry after failures."""
    if outcome not in {"sent", "failed", "skipped"}:
        raise ValueError("Outcome must be sent, failed, or skipped.")
    if base_delay_seconds < 1 or max_delay_seconds < base_delay_seconds or max_delay_seconds > 86400:
        raise ValueError("Retry delay must be positive; max delay must be >= base delay and <= 86400 seconds.")
    if max_attempts < 1 or max_attempts > 100:
        raise ValueError("Maximum attempts must be between 1 and 100.")
    now = _now(); now_text = _iso(now)
    with connect(repo.db_path) as db:
        row = db.execute("SELECT delivery_attempts, lease_owner, status FROM notification_events WHERE id=?", (event_id,)).fetchone()
        if row is None or row["status"] not in {"pending", "acknowledged"}:
            raise ValueError(f"Notification event #{event_id} cannot be finished.")
        if row["lease_owner"] != worker_id:
            raise PermissionError("Worker does not own the active event lease.")
        attempts = int(row["delivery_attempts"]) + (1 if outcome in {"sent", "failed"} else 0)
        next_attempt = None
        quarantine = outcome == "failed" and attempts >= max_attempts
        if outcome == "failed" and not quarantine:
            delay = min(base_delay_seconds * (2 ** min(max(attempts - 1, 0), 16)), max_delay_seconds)
            next_attempt = _iso(now + timedelta(seconds=delay))
        if quarantine:
            db.execute("INSERT INTO notification_dead_letters(event_id, reason, attempts) VALUES(?,?,?) ON CONFLICT(event_id) DO UPDATE SET reason=excluded.reason, attempts=excluded.attempts, quarantined_at=strftime('%Y-%m-%dT%H:%M:%fZ','now'), resolved_at=NULL", (event_id, (error or "Maximum delivery attempts reached")[:500], attempts))
        if outcome == "sent":
            db.execute("UPDATE notification_events SET status='acknowledged', delivery_attempts=?, next_attempt_at=NULL, last_delivery_error=NULL, lease_owner=NULL, lease_until=NULL, updated_at=? WHERE id=? AND lease_owner=?", (attempts, now_text, event_id, worker_id))
        else:
            db.execute("UPDATE notification_events SET delivery_attempts=?, next_attempt_at=?, last_delivery_error=?, lease_owner=NULL, lease_until=NULL, updated_at=? WHERE id=? AND lease_owner=?", (attempts, next_attempt, (error or "")[:500] or None, now_text, event_id, worker_id))
    return {"event_id": event_id, "outcome": outcome, "delivery_attempts": attempts,
            "next_attempt_at": next_attempt, "lease_released": True,
            "quarantined": bool(outcome == "failed" and attempts >= max_attempts)}


def release_claim(repo, event_id: int, worker_id: str) -> bool:
    with connect(repo.db_path) as db:
        changed = db.execute("UPDATE notification_events SET lease_owner=NULL, lease_until=NULL WHERE id=? AND status='pending' AND lease_owner=?", (event_id, worker_id)).rowcount
    return changed == 1


def list_dead_letters(repo, *, include_resolved: bool = False, limit: int = 100) -> list[dict]:
    if limit < 1 or limit > 1000:
        raise ValueError("Dead-letter limit must be between 1 and 1000.")
    query = "SELECT d.*, e.title, e.event_type, e.severity, e.status AS event_status FROM notification_dead_letters d JOIN notification_events e ON e.id=d.event_id"
    if not include_resolved:
        query += " WHERE d.resolved_at IS NULL"
    query += " ORDER BY d.id DESC LIMIT ?"
    with connect(repo.db_path) as db:
        return [dict(row) for row in db.execute(query, (limit,)).fetchall()]


def resolve_dead_letter(repo, event_id: int) -> bool:
    """Remove an event from quarantine and make it eligible for a deliberate retry."""
    with connect(repo.db_path) as db:
        changed = db.execute("UPDATE notification_dead_letters SET resolved_at=strftime('%Y-%m-%dT%H:%M:%fZ','now') WHERE event_id=? AND resolved_at IS NULL", (event_id,)).rowcount
        if changed:
            db.execute("UPDATE notification_events SET next_attempt_at=NULL, lease_owner=NULL, lease_until=NULL WHERE id=? AND status='pending'", (event_id,))
    return changed == 1
