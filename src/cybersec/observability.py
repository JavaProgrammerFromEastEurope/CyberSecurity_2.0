"""Local-only queue diagnostics and durable delivery metrics."""
from __future__ import annotations

from datetime import datetime, timezone

from cybersec.db import connect
from cybersec.delivery_queue import queue_stats


def _now_text() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="milliseconds").replace("+00:00", "Z")


def queue_metrics(repo) -> dict:
    """Return database-derived counters; does not perform network requests."""
    stats = queue_stats(repo)
    with connect(repo.db_path) as db:
        row = db.execute("""
            SELECT COUNT(*) AS total_attempts,
                   SUM(CASE WHEN outcome='sent' THEN 1 ELSE 0 END) AS sent,
                   SUM(CASE WHEN outcome='failed' THEN 1 ELSE 0 END) AS failed,
                   SUM(CASE WHEN outcome='skipped' THEN 1 ELSE 0 END) AS skipped,
                   MAX(created_at) AS last_attempt_at
            FROM notification_deliveries
        """).fetchone()
        attempts = {key: (row[key] or 0) for key in ("total_attempts", "sent", "failed", "skipped")}
        attempts["last_attempt_at"] = row["last_attempt_at"]
        dead = db.execute("SELECT COUNT(*) FROM notification_dead_letters WHERE resolved_at IS NULL").fetchone()[0]
    return {"schema_version": 1, "generated_at": _now_text(), "queue": stats,
            "delivery_attempts": attempts, "open_dead_letters": dead}


def queue_diagnostics(repo) -> dict:
    """Inspect queue health and SQLite integrity without changing queue state."""
    now = _now_text()
    with connect(repo.db_path) as db:
        integrity = db.execute("PRAGMA integrity_check").fetchone()[0]
        stale = db.execute("SELECT COUNT(*) FROM notification_events WHERE status='pending' AND lease_owner IS NOT NULL AND lease_until<=?", (now,)).fetchone()[0]
        oldest = db.execute("SELECT MIN(created_at) FROM notification_events WHERE status='pending'").fetchone()[0]
        recent_errors = [dict(row) for row in db.execute("""
            SELECT id AS event_id, delivery_attempts, last_delivery_error, updated_at
            FROM notification_events WHERE last_delivery_error IS NOT NULL
            ORDER BY updated_at DESC, id DESC LIMIT 10
        """).fetchall()]
    stats = queue_stats(repo)
    warnings = []
    if integrity != "ok": warnings.append("sqlite_integrity_check_failed")
    if stale: warnings.append("expired_leases_present")
    if stats["quarantined"]: warnings.append("open_dead_letters_present")
    if stats["due_pending"]: warnings.append("pending_events_due")
    return {"schema_version": 1, "generated_at": now,
            "healthy": integrity == "ok", "sqlite_integrity": integrity,
            "queue": stats, "expired_leases": stale,
            "oldest_pending_created_at": oldest, "recent_errors": recent_errors,
            "warnings": warnings}
