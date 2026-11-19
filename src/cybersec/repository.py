"""Repository methods for targets, jobs, and findings."""
from __future__ import annotations

import hashlib
import json
import re
import sqlite3
from urllib.parse import urlsplit, urlunsplit
from pathlib import Path

from cybersec.db import connect, initialize
from cybersec.models import Finding, ScanJob, Target
from cybersec.scope import normalize_target_url
from cybersec.risk import assess_risk, normalize_vuln_type


class Repository:
    def __init__(self, db_path: str | Path):
        self.db_path = Path(db_path)
        initialize(self.db_path)
        self._backfill_fingerprints()

    def add_target(self, url: str, authorized: bool) -> Target:
        normalized, hostname = normalize_target_url(url)
        with connect(self.db_path) as db:
            db.execute(
                "INSERT INTO targets(url, hostname, authorized) VALUES (?, ?, ?) "
                "ON CONFLICT(url) DO UPDATE SET authorized = MAX(targets.authorized, excluded.authorized)",
                (normalized, hostname, int(authorized)),
            )
            row = db.execute("SELECT * FROM targets WHERE url = ?", (normalized,)).fetchone()
        return Target(row["id"], row["url"], row["hostname"], bool(row["authorized"]), row["created_at"], row["criticality"] if "criticality" in row.keys() else "medium")

    def list_targets(self) -> list[Target]:
        with connect(self.db_path) as db:
            rows = db.execute("SELECT * FROM targets ORDER BY id").fetchall()
        return [Target(r["id"], r["url"], r["hostname"], bool(r["authorized"]), r["created_at"], r["criticality"] if "criticality" in r.keys() else "medium") for r in rows]

    def set_target_criticality(self, target_id: int, criticality: str) -> Target:
        """Set analyst-provided business criticality for a registered target."""
        value = str(criticality).strip().lower()
        if value not in {"low", "medium", "high", "critical"}:
            raise ValueError("criticality must be low, medium, high, or critical")
        with connect(self.db_path) as db:
            cursor = db.execute("UPDATE targets SET criticality = ? WHERE id = ?", (value, target_id))
            if cursor.rowcount != 1:
                raise ValueError(f"Target #{target_id} does not exist.")
            row = db.execute("SELECT * FROM targets WHERE id = ?", (target_id,)).fetchone()
        return Target(row["id"], row["url"], row["hostname"], bool(row["authorized"]), row["created_at"], row["criticality"])

    def get_target_by_url(self, url: str) -> Target | None:
        normalized, _ = normalize_target_url(url)
        with connect(self.db_path) as db:
            row = db.execute("SELECT * FROM targets WHERE url = ?", (normalized,)).fetchone()
        if row is None:
            return None
        return Target(row["id"], row["url"], row["hostname"], bool(row["authorized"]), row["created_at"], row["criticality"] if "criticality" in row.keys() else "medium")

    def create_job(self, target_url: str, tool: str) -> ScanJob:
        target = self.get_target_by_url(target_url)
        if target is None:
            raise ValueError("Target is not registered. Add it first with `target add`.")
        if not target.authorized:
            raise PermissionError("Target is not marked as authorized. Re-add it with --authorized after obtaining permission.")
        tool = tool.strip().lower()
        if not tool or tool not in {"demo", "zap", "nuclei", "sqlmap"}:
            raise ValueError("Tool must be one of: demo, zap, nuclei, sqlmap.")
        with connect(self.db_path) as db:
            cursor = db.execute("INSERT INTO scan_jobs(target_id, tool) VALUES (?, ?)", (target.id, tool))
            row = db.execute("SELECT * FROM scan_jobs WHERE id = ?", (cursor.lastrowid,)).fetchone()
        return self._job(row)


    def claim_next_scan_job(self, worker_id: str, *, lease_seconds: int = 60,
                             max_attempts: int = 3) -> ScanJob | None:
        """Atomically claim one eligible scan job using a SQLite write lock."""
        worker_id = str(worker_id).strip()
        if not worker_id or len(worker_id) > 128:
            raise ValueError("worker_id must contain 1-128 characters.")
        if not 5 <= int(lease_seconds) <= 3600:
            raise ValueError("lease_seconds must be between 5 and 3600.")
        if not 1 <= int(max_attempts) <= 20:
            raise ValueError("max_attempts must be between 1 and 20.")
        with connect(self.db_path) as db:
            db.execute("BEGIN IMMEDIATE")
            # Cancellation is terminal after the owner has stopped or its lease expires.
            # Never reclaim cancelled work: the original scanner may still be winding down.
            db.execute(
                """UPDATE scan_jobs SET status='cancelled',
                       finished_at=strftime('%Y-%m-%dT%H:%M:%fZ','now'),
                       lease_owner=NULL, lease_until=NULL,
                       error=COALESCE(error, 'Cancellation requested; worker lease expired.')
                   WHERE status='running' AND cancel_requested_at IS NOT NULL
                     AND lease_until IS NOT NULL
                     AND lease_until <= strftime('%Y-%m-%dT%H:%M:%fZ','now')"""
            )
            # External scanner effects are not transactional. A lost worker may
            # still have a live subprocess: never automatically re-execute it.
            db.execute(
                """UPDATE scan_jobs SET status='failed',
                       finished_at=strftime('%Y-%m-%dT%H:%M:%fZ','now'),
                       error='External scanner lease expired; manual recovery required (execution state unknown).',
                       lease_owner=NULL, lease_until=NULL
                   WHERE status='running' AND tool <> 'demo'
                     AND cancel_requested_at IS NULL AND lease_until IS NOT NULL
                     AND lease_until <= strftime('%Y-%m-%dT%H:%M:%fZ','now')"""
            )
            # Exhausted expired leases are terminally failed rather than claimed forever.
            db.execute(
                """UPDATE scan_jobs
                   SET status='failed', finished_at=strftime('%Y-%m-%dT%H:%M:%fZ','now'),
                       error=COALESCE(error, 'Worker lease expired; retry limit reached.'),
                       lease_owner=NULL, lease_until=NULL
                   WHERE status='running' AND lease_until IS NOT NULL
                     AND lease_until <= strftime('%Y-%m-%dT%H:%M:%fZ','now')
                     AND attempt_count >= ?""", (max_attempts,)
            )
            row = db.execute(
                """SELECT * FROM scan_jobs
                   WHERE cancel_requested_at IS NULL AND attempt_count < ?
                     AND tool <> 'sqlmap' AND (status='queued' OR
                          (status='running' AND tool='demo' AND lease_until IS NOT NULL
                           AND lease_until <= strftime('%Y-%m-%dT%H:%M:%fZ','now')))
                   ORDER BY created_at, id LIMIT 1""", (max_attempts,)
            ).fetchone()
            if row is None:
                return None
            cursor = db.execute(
                """UPDATE scan_jobs
                   SET status='running',
                       started_at=COALESCE(started_at, strftime('%Y-%m-%dT%H:%M:%fZ','now')),
                       finished_at=NULL, error=NULL, lease_owner=?,
                       lease_until=strftime('%Y-%m-%dT%H:%M:%fZ','now', ?),
                       attempt_count=attempt_count+1, max_attempts=?
                   WHERE id=? AND (
                       status='queued' OR
                       (status='running' AND lease_until IS NOT NULL
                        AND lease_until <= strftime('%Y-%m-%dT%H:%M:%fZ','now'))
                   )""",
                (worker_id, f"+{int(lease_seconds)} seconds", max_attempts, row["id"])
            )
            if cursor.rowcount != 1:
                return None
            claimed = db.execute("SELECT * FROM scan_jobs WHERE id=?", (row["id"],)).fetchone()
        return self._job(claimed)

    def request_manual_scan_recovery(self, job_id: int, *, acknowledged_by: str,
                                     external_process_stopped: bool) -> ScanJob:
        """Create a fresh auditable job only after an operator confirms process stop.

        This does not kill remote scanners or guarantee exactly-once execution.
        SQLmap requires its separate finding-linked approval flow and is excluded.
        """
        actor = str(acknowledged_by).strip()
        if not actor or len(actor) > 128:
            raise ValueError('acknowledged_by must contain 1-128 characters')
        if external_process_stopped is not True:
            raise PermissionError('External process termination must be verified before recovery')
        with connect(self.db_path) as db:
            db.execute('BEGIN IMMEDIATE')
            old = db.execute('SELECT * FROM scan_jobs WHERE id=?', (job_id,)).fetchone()
            if old is None:
                raise ValueError(f'Scan job #{job_id} does not exist')
            if old['tool'] == 'sqlmap':
                raise PermissionError('SQLmap requires finding-linked approval, not generic recovery')
            if old['status'] != 'failed' or not old['error'] or 'manual recovery required' not in old['error']:
                raise ValueError('Only uncertain external scanner failures can be manually recovered')
            target = db.execute('SELECT authorized FROM targets WHERE id=?', (old['target_id'],)).fetchone()
            if target is None or not target['authorized']:
                raise PermissionError('Target is no longer authorized')
            cursor = db.execute('INSERT INTO scan_jobs(target_id, tool) VALUES (?, ?)',
                                (old['target_id'], old['tool']))
            new = db.execute('SELECT * FROM scan_jobs WHERE id=?', (cursor.lastrowid,)).fetchone()
            # Explicit recovery record, bound to original job and accountable actor.
            db.execute('INSERT INTO scan_recovery_audit(old_job_id, new_job_id, acknowledged_by) VALUES (?, ?, ?)',
                       (job_id, new['id'], actor))
        return self._job(new)

    def renew_scan_job_lease(self, job_id: int, worker_id: str, *, lease_seconds: int = 60) -> bool:
        if not 5 <= int(lease_seconds) <= 3600:
            raise ValueError("lease_seconds must be between 5 and 3600.")
        with connect(self.db_path) as db:
            cursor = db.execute(
                """UPDATE scan_jobs SET lease_until=strftime('%Y-%m-%dT%H:%M:%fZ','now', ?)
                   WHERE id=? AND status='running' AND lease_owner=?
                     AND lease_until > strftime('%Y-%m-%dT%H:%M:%fZ','now')""",
                (f"+{int(lease_seconds)} seconds", job_id, worker_id)
            )
        return cursor.rowcount == 1

    def assert_active_scan_lease(self, job_id: int, worker_id: str) -> None:
        """Fence stale worker results; cancellation still permits orderly completion."""
        with connect(self.db_path) as db:
            row = db.execute(
                """SELECT 1 FROM scan_jobs WHERE id=? AND status='running'
                   AND lease_owner=? AND lease_until > strftime('%Y-%m-%dT%H:%M:%fZ','now')""",
                (job_id, worker_id),
            ).fetchone()
        if row is None:
            raise RuntimeError(f"Worker {worker_id!r} has no active lease for scan job #{job_id}.")

    def inspect_scan_execution(self, job_id: int, worker_id: str, attempt: int) -> str:
        """Read-only signal for worker abort; no lease extension or status mutation."""
        with connect(self.db_path) as db:
            row = db.execute(
                """SELECT status, lease_owner, attempt_count, lease_until, cancel_requested_at
                   FROM scan_jobs WHERE id=?""", (job_id,)
            ).fetchone()
            if row is None or row["status"] != "running" or row["lease_owner"] != worker_id \
                    or row["attempt_count"] != attempt or row["lease_until"] is None:
                return "lost"
            if row["cancel_requested_at"] is not None:
                return "cancelled"
            valid = db.execute(
                """SELECT 1 FROM scan_jobs WHERE id=?
                   AND lease_until > strftime('%Y-%m-%dT%H:%M:%fZ','now')""", (job_id,)
            ).fetchone()
            return "active" if valid is not None else "lost"

    def finish_claimed_scan_job(self, job_id: int, worker_id: str, *,
                                error: str | None = None,
                                attempt: int | None = None) -> ScanJob:
        if attempt is not None and (not isinstance(attempt, int) or isinstance(attempt, bool) or attempt < 1):
            raise ValueError("attempt must be a positive integer")
        status = "failed" if error else "completed"
        with connect(self.db_path) as db:
            cursor = db.execute(
                """UPDATE scan_jobs SET
                       status=CASE WHEN cancel_requested_at IS NOT NULL THEN 'cancelled' ELSE ? END,
                       finished_at=strftime('%Y-%m-%dT%H:%M:%fZ','now'),
                       error=CASE WHEN cancel_requested_at IS NOT NULL
                                  THEN 'Cancellation requested.' ELSE ? END,
                       lease_owner=NULL, lease_until=NULL
                   WHERE id=? AND status='running' AND lease_owner=?
                     AND lease_until > strftime('%Y-%m-%dT%H:%M:%fZ','now')
                     AND (? IS NULL OR attempt_count=?)""",
                (status, error, job_id, worker_id, attempt, attempt)
            )
            if cursor.rowcount != 1:
                raise RuntimeError(f"Worker {worker_id!r} no longer owns scan job #{job_id}.")
            row = db.execute("SELECT * FROM scan_jobs WHERE id=?", (job_id,)).fetchone()
        return self._job(row)

    def cancel_scan_job(self, job_id: int) -> ScanJob:
        """Cancel queued work or request cooperative cancellation of a running job."""
        with connect(self.db_path) as db:
            cursor = db.execute(
                """UPDATE scan_jobs
                   SET status=CASE WHEN status='queued' THEN 'cancelled' ELSE status END,
                       cancel_requested_at=strftime('%Y-%m-%dT%H:%M:%fZ','now'),
                       finished_at=CASE WHEN status='queued' THEN strftime('%Y-%m-%dT%H:%M:%fZ','now') ELSE finished_at END,
                       lease_owner=CASE WHEN status='queued' THEN NULL ELSE lease_owner END,
                       lease_until=CASE WHEN status='queued' THEN NULL ELSE lease_until END
                   WHERE id=? AND status IN ('queued','running')""", (job_id,)
            )
            if cursor.rowcount != 1:
                row = db.execute("SELECT status FROM scan_jobs WHERE id=?", (job_id,)).fetchone()
                if row is None: raise ValueError(f"Job #{job_id} does not exist.")
                raise ValueError(f"Cannot cancel job #{job_id} from status '{row['status']}'.")
            row = db.execute("SELECT * FROM scan_jobs WHERE id=?", (job_id,)).fetchone()
        return self._job(row)

    def list_jobs(self) -> list[ScanJob]:
        with connect(self.db_path) as db:
            rows = db.execute("SELECT * FROM scan_jobs ORDER BY id DESC").fetchall()
        return [self._job(r) for r in rows]


    def get_job(self, job_id: int) -> ScanJob | None:
        with connect(self.db_path) as db:
            row = db.execute("SELECT * FROM scan_jobs WHERE id = ?", (job_id,)).fetchone()
        return self._job(row) if row is not None else None

    def get_target_by_id(self, target_id: int) -> Target | None:
        with connect(self.db_path) as db:
            row = db.execute("SELECT * FROM targets WHERE id = ?", (target_id,)).fetchone()
        if row is None:
            return None
        return Target(row["id"], row["url"], row["hostname"], bool(row["authorized"]), row["created_at"], row["criticality"] if "criticality" in row.keys() else "medium")

    def start_job(self, job_id: int) -> ScanJob:
        """Move a queued job to running; reject invalid state transitions."""
        with connect(self.db_path) as db:
            cursor = db.execute(
                "UPDATE scan_jobs SET status = 'running', started_at = strftime('%Y-%m-%dT%H:%M:%fZ', 'now'), error = NULL "
                "WHERE id = ? AND status = 'queued'", (job_id,)
            )
            if cursor.rowcount != 1:
                row = db.execute("SELECT status FROM scan_jobs WHERE id = ?", (job_id,)).fetchone()
                if row is None:
                    raise ValueError(f"Job #{job_id} does not exist.")
                raise ValueError(f"Cannot start job #{job_id} from status '{row['status']}'.")
            row = db.execute("SELECT * FROM scan_jobs WHERE id = ?", (job_id,)).fetchone()
        return self._job(row)

    def finish_job(self, job_id: int, *, error: str | None = None) -> ScanJob:
        """Finish a running job as completed or failed."""
        status = "failed" if error else "completed"
        with connect(self.db_path) as db:
            cursor = db.execute(
                "UPDATE scan_jobs SET status = ?, finished_at = strftime('%Y-%m-%dT%H:%M:%fZ', 'now'), error = ? "
                "WHERE id = ? AND status = 'running'", (status, error, job_id)
            )
            if cursor.rowcount != 1:
                row = db.execute("SELECT status FROM scan_jobs WHERE id = ?", (job_id,)).fetchone()
                if row is None:
                    raise ValueError(f"Job #{job_id} does not exist.")
                raise ValueError(f"Cannot finish job #{job_id} from status '{row['status']}'.")
            row = db.execute("SELECT * FROM scan_jobs WHERE id = ?", (job_id,)).fetchone()
        return self._job(row)

    def cancel_job(self, job_id: int) -> ScanJob:
        """Cancel a queued job. Running-job cancellation will be added with worker support."""
        with connect(self.db_path) as db:
            cursor = db.execute(
                "UPDATE scan_jobs SET status = 'cancelled', finished_at = strftime('%Y-%m-%dT%H:%M:%fZ', 'now') "
                "WHERE id = ? AND status = 'queued'", (job_id,)
            )
            if cursor.rowcount != 1:
                row = db.execute("SELECT status FROM scan_jobs WHERE id = ?", (job_id,)).fetchone()
                if row is None:
                    raise ValueError(f"Job #{job_id} does not exist.")
                raise ValueError(f"Only queued jobs can be cancelled; job #{job_id} is '{row['status']}'.")
            row = db.execute("SELECT * FROM scan_jobs WHERE id = ?", (job_id,)).fetchone()
        return self._job(row)

    @staticmethod
    def _canonical_finding_url(url: str) -> str:
        """Normalize URL identity without changing query parameters or scope."""
        try:
            parts = urlsplit(url.strip())
            scheme = parts.scheme.lower()
            netloc = parts.netloc.lower()
            path = parts.path or "/"
            if path != "/":
                path = path.rstrip("/") or "/"
            return urlunsplit((scheme, netloc, path, parts.query, ""))
        except ValueError:
            return url.strip()

    @classmethod
    def _fingerprint(cls, target_id: int, url: str, parameter: str | None, vuln_type: str) -> str:
        normalized_type = normalize_vuln_type(vuln_type)
        payload = [target_id, cls._canonical_finding_url(url), (parameter or "").strip().casefold(), normalized_type]
        return hashlib.sha256(json.dumps(payload, separators=(",", ":"), ensure_ascii=True).encode()).hexdigest()

    def _backfill_fingerprints(self) -> None:
        """Give legacy findings stable fingerprints, merging collisions conservatively."""
        with connect(self.db_path) as db:
            rows = db.execute("SELECT * FROM normalized_findings WHERE fingerprint IS NULL ORDER BY id").fetchall()
            for row in rows:
                fp = self._fingerprint(row["target_id"], row["url"], row["parameter"], row["vuln_type"])
                existing = db.execute("SELECT id FROM normalized_findings WHERE fingerprint = ?", (fp,)).fetchone()
                if existing:
                    duplicate = db.execute("SELECT * FROM normalized_findings WHERE id = ?", (row["id"],)).fetchone()
                    keeper = db.execute("SELECT * FROM normalized_findings WHERE id = ?", (existing["id"],)).fetchone()
                    severity_rank = {"Info": 0, "Low": 1, "Medium": 2, "High": 3, "Critical": 4}
                    confidence_rank = {"Unknown": 0, "Tentative": 1, "Firm": 2, "Certain": 3}
                    severity = max((keeper["severity"], duplicate["severity"]), key=lambda x: severity_rank[x])
                    confidence = max((keeper["confidence"], duplicate["confidence"]), key=lambda x: confidence_rank[x])
                    sources = sorted(set(keeper["source_tool"].split(",")) | set(duplicate["source_tool"].split(",")))
                    evidence = "\n---\n".join(dict.fromkeys(x for x in (keeper["evidence"], duplicate["evidence"]) if x)) or None
                    recommendation = "\n---\n".join(dict.fromkeys(x for x in (keeper["recommendation"], duplicate["recommendation"]) if x)) or None
                    db.execute("UPDATE normalized_findings SET severity=?, confidence=?, evidence=?, recommendation=?, source_tool=? WHERE id=?",
                               (severity, confidence, evidence, recommendation, ",".join(sources), keeper["id"]))
                    db.execute("DELETE FROM normalized_findings WHERE id = ?", (row["id"],))
                else:
                    db.execute("UPDATE normalized_findings SET fingerprint = ? WHERE id = ?", (fp, row["id"]))

    def add_finding(
        self, target_url: str, title: str, severity: str, confidence: str,
        vuln_type: str, url: str | None = None, parameter: str | None = None,
        evidence: str | None = None, recommendation: str | None = None,
        source_tool: str = "manual", job_id: int | None = None,
        source_id: str | None = None, template_id: str | None = None,
        observed_at: str | None = None,
    ) -> Finding:
        target = self.get_target_by_url(target_url)
        if target is None:
            raise ValueError("Target is not registered.")
        severity = severity.title()
        confidence = confidence.title()
        if severity not in {"Critical", "High", "Medium", "Low", "Info"}:
            raise ValueError("Severity must be Critical, High, Medium, Low, or Info.")
        if confidence not in {"Certain", "Firm", "Tentative", "Unknown"}:
            raise ValueError("Confidence must be Certain, Firm, Tentative, or Unknown.")
        title = title.strip()
        vuln_type = normalize_vuln_type(vuln_type)
        source_tool = source_tool.strip().lower() or "manual"
        finding_url = self._canonical_finding_url(url or target.url)
        fingerprint = self._fingerprint(target.id, finding_url, parameter, vuln_type)
        severity_rank = {"Info": 0, "Low": 1, "Medium": 2, "High": 3, "Critical": 4}
        confidence_rank = {"Unknown": 0, "Tentative": 1, "Firm": 2, "Certain": 3}
        with connect(self.db_path) as db:
            existing = db.execute("SELECT * FROM normalized_findings WHERE fingerprint = ?", (fingerprint,)).fetchone()
            if existing:
                best_severity = max((existing["severity"], severity), key=lambda x: severity_rank[x])
                best_confidence = max((existing["confidence"], confidence), key=lambda x: confidence_rank[x])
                sources = sorted(set(existing["source_tool"].split(",")) | {source_tool})
                evidence_parts = [x for x in (existing["evidence"], evidence) if x]
                merged_evidence = "\n---\n".join(dict.fromkeys(evidence_parts)) or None
                recommendations = [x for x in (existing["recommendation"], recommendation) if x]
                merged_recommendation = "\n---\n".join(dict.fromkeys(recommendations)) or None
                merged_title = existing["title"] if len(existing["title"]) >= len(title) else title
                db.execute(
                    """UPDATE normalized_findings SET title=?, severity=?, confidence=?, evidence=?, recommendation=?, source_tool=?,
                    source_id=COALESCE(source_id, ?), template_id=COALESCE(template_id, ?), observed_at=COALESCE(observed_at, ?)
                    WHERE id=?""",
                    (merged_title, best_severity, best_confidence, merged_evidence, merged_recommendation,
                     ",".join(sources), source_id, template_id, observed_at, existing["id"]),
                )
                row = db.execute("SELECT * FROM normalized_findings WHERE id = ?", (existing["id"],)).fetchone()
                db.execute("INSERT INTO finding_observations(finding_id,job_id,severity,observed_at) VALUES(?,?,?,COALESCE(?,strftime('%Y-%m-%dT%H:%M:%fZ','now')))",
                           (row["id"], job_id, severity, observed_at))
            else:
                cursor = db.execute(
                    """INSERT INTO normalized_findings
                    (target_id, job_id, title, severity, confidence, url, vuln_type,
                     parameter, evidence, recommendation, source_tool, fingerprint,
                     source_id, template_id, observed_at)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                    (target.id, job_id, title, severity, confidence, finding_url, vuln_type,
                     parameter, evidence, recommendation, source_tool, fingerprint,
                     source_id, template_id, observed_at),
                )
                row = db.execute("SELECT * FROM normalized_findings WHERE id = ?", (cursor.lastrowid,)).fetchone()
                db.execute("INSERT INTO finding_observations(finding_id,job_id,severity,observed_at) VALUES(?,?,?,COALESCE(?,strftime('%Y-%m-%dT%H:%M:%fZ','now')))",
                           (row["id"], job_id, severity, observed_at))
        return self._finding(row)

    def store_scan_artifact(self, job_id: int, source_tool: str, raw_payload: object, *,
                            status: str = "complete", metadata: dict | None = None) -> dict:
        """Retain raw scanner output idempotently, preserving malformed/partial payloads."""
        if status not in {"complete", "partial", "corrupt"}:
            raise ValueError("Artifact status must be complete, partial, or corrupt.")
        with connect(self.db_path) as db:
            job = db.execute("SELECT id FROM scan_jobs WHERE id = ?", (job_id,)).fetchone()
            if job is None:
                raise ValueError(f"Job #{job_id} does not exist.")
            if isinstance(raw_payload, str):
                try:
                    parsed = json.loads(raw_payload)
                    payload = json.dumps(parsed, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
                    payload_format = "json"
                except (json.JSONDecodeError, TypeError):
                    payload = raw_payload
                    payload_format = "text"
                    if status == "complete":
                        status = "corrupt"
            else:
                try:
                    payload = json.dumps(raw_payload, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
                    payload_format = "json"
                except (TypeError, ValueError) as exc:
                    payload = repr(raw_payload)
                    payload_format = "text"
                    if status == "complete":
                        status = "corrupt"
            source_tool = source_tool.strip().lower()
            if not source_tool:
                raise ValueError("Artifact source_tool cannot be empty.")
            digest = hashlib.sha256((payload_format + "\0" + payload).encode("utf-8")).hexdigest()
            metadata_json = json.dumps(metadata or {}, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
            db.execute("""INSERT INTO scan_artifacts(job_id, source_tool, content_hash, payload,
                payload_format, status, metadata) VALUES (?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(job_id, source_tool, content_hash) DO NOTHING""",
                (job_id, source_tool, digest, payload, payload_format, status, metadata_json))
            row = db.execute("SELECT * FROM scan_artifacts WHERE job_id=? AND source_tool=? AND content_hash=?",
                             (job_id, source_tool, digest)).fetchone()
        return dict(row)

    def commit_claimed_scan_result(self, job_id: int, worker_id: str, attempt: int,
                                   source_tool: str, raw_payload: object, *,
                                   adapter_status: str = "completed", summary: str = "",
                                   finding_count: int = 0) -> tuple[dict | None, ScanJob]:
        """Atomically fence, persist and finish a worker attempt.

        The monotonically increasing attempt_count is a fencing token, even if
        a worker identifier is reused. Cancellation commits no result artifact.
        """
        if not isinstance(attempt, int) or isinstance(attempt, bool) or attempt < 1:
            raise ValueError("attempt must be a positive integer")
        if adapter_status not in {"completed", "failed", "partial"}:
            raise ValueError("unsupported adapter status")
        source_tool = source_tool.strip().lower()
        if not source_tool:
            raise ValueError("Artifact source_tool cannot be empty.")
        try:
            payload = json.dumps(raw_payload, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
            payload_format = "json"
        except (TypeError, ValueError):
            payload = repr(raw_payload)
            payload_format = "text"
        digest = hashlib.sha256((payload_format + "\0" + payload).encode("utf-8")).hexdigest()
        metadata = json.dumps({"adapter_status": adapter_status, "finding_count": finding_count},
                              sort_keys=True, separators=(",", ":"), ensure_ascii=False)
        with connect(self.db_path) as db:
            db.execute("BEGIN IMMEDIATE")
            job = db.execute(
                """SELECT * FROM scan_jobs WHERE id=? AND status='running'
                   AND lease_owner=? AND attempt_count=?
                   AND lease_until > strftime('%Y-%m-%dT%H:%M:%fZ','now')""",
                (job_id, worker_id, attempt),
            ).fetchone()
            if job is None:
                raise RuntimeError("Stale or expired scanner lease; result rejected")
            artifact = None
            if job["cancel_requested_at"] is None:
                db.execute(
                    """INSERT INTO scan_artifacts(job_id, source_tool, content_hash, payload,
                       payload_format, status, metadata) VALUES (?, ?, ?, ?, ?, ?, ?)
                       ON CONFLICT(job_id, source_tool, content_hash) DO NOTHING""",
                    (job_id, source_tool, digest, payload, payload_format,
                     "complete" if adapter_status == "completed" and payload_format == "json" else "partial", metadata),
                )
                artifact = dict(db.execute(
                    "SELECT * FROM scan_artifacts WHERE job_id=? AND source_tool=? AND content_hash=?",
                    (job_id, source_tool, digest),
                ).fetchone())
            status = ("cancelled" if job["cancel_requested_at"] is not None else
                      "completed" if adapter_status == "completed" else "failed")
            error = ("Cancellation requested." if status == "cancelled" else
                     (summary or f"Adapter returned status '{adapter_status}'.") if status == "failed" else None)
            updated = db.execute(
                """UPDATE scan_jobs SET status=?, error=?,
                   finished_at=strftime('%Y-%m-%dT%H:%M:%fZ','now'),
                   lease_owner=NULL, lease_until=NULL
                   WHERE id=? AND status='running' AND lease_owner=? AND attempt_count=?
                     AND lease_until > strftime('%Y-%m-%dT%H:%M:%fZ','now')""",
                (status, error, job_id, worker_id, attempt),
            )
            if updated.rowcount != 1:
                raise RuntimeError("Lost scanner lease while committing result")
            final_job = db.execute("SELECT * FROM scan_jobs WHERE id=?", (job_id,)).fetchone()
        return artifact, self._job(final_job)

    def get_scan_artifact(self, artifact_id: int) -> dict | None:
        with connect(self.db_path) as db:
            row = db.execute("SELECT * FROM scan_artifacts WHERE id=?", (artifact_id,)).fetchone()
        if row is None:
            return None
        item = dict(row)
        try:
            item["metadata"] = json.loads(item["metadata"])
        except (TypeError, json.JSONDecodeError):
            item["metadata"] = {}
        return item

    def search_scan_artifacts(self, *, job_id: int | None = None, source_tool: str | None = None,
                              status: str | None = None, query: str | None = None) -> list[dict]:
        clauses: list[str] = []
        params: list[object] = []
        if job_id is not None:
            clauses.append("job_id=?"); params.append(job_id)
        if source_tool:
            clauses.append("source_tool=?"); params.append(source_tool.strip().lower())
        if status:
            clauses.append("status=?"); params.append(status)
        if query:
            clauses.append("(payload LIKE ? OR metadata LIKE ? OR content_hash LIKE ?)")
            pattern = f"%{query}%"; params.extend((pattern, pattern, pattern))
        sql = "SELECT * FROM scan_artifacts" + (" WHERE " + " AND ".join(clauses) if clauses else "") + " ORDER BY id"
        with connect(self.db_path) as db:
            rows = db.execute(sql, params).fetchall()
        result = []
        for row in rows:
            item = dict(row)
            try: item["metadata"] = json.loads(item["metadata"])
            except (TypeError, json.JSONDecodeError): item["metadata"] = {}
            result.append(item)
        return result

    def list_scan_artifacts(self, job_id: int | None = None) -> list[dict]:
        return self.search_scan_artifacts(job_id=job_id)

    def save_comparison(self, result: dict) -> dict:
        """Persist the latest comparison snapshot for a unique ordered job pair."""
        comparison = result.get("comparison", {})
        before_id = int(comparison["before_job"]["id"])
        after_id = int(comparison["after_job"]["id"])
        if before_id == after_id:
            raise ValueError("A comparison must use two different jobs.")
        rendered = json.dumps(result, sort_keys=True, ensure_ascii=False, separators=(",", ":"))
        summary = json.dumps(result.get("summary", {}), sort_keys=True, ensure_ascii=False)
        with connect(self.db_path) as db:
            db.execute(
                "INSERT INTO comparison_history(before_job_id, after_job_id, schema_version, summary_json, result_json) "
                "VALUES (?, ?, ?, ?, ?) ON CONFLICT(before_job_id, after_job_id) DO UPDATE SET "
                "schema_version=excluded.schema_version, summary_json=excluded.summary_json, "
                "result_json=excluded.result_json, created_at=strftime('%Y-%m-%dT%H:%M:%fZ', 'now')",
                (before_id, after_id, int(result.get("schema_version", 1)), summary, rendered),
            )
            row = db.execute(
                "SELECT * FROM comparison_history WHERE before_job_id=? AND after_job_id=?",
                (before_id, after_id),
            ).fetchone()
        item = dict(row)
        item["summary"] = json.loads(item.pop("summary_json"))
        item["result"] = json.loads(item.pop("result_json"))
        return item

    def list_comparisons(self, *, limit: int = 100) -> list[dict]:
        if limit < 1 or limit > 1000:
            raise ValueError("History limit must be between 1 and 1000.")
        with connect(self.db_path) as db:
            rows = db.execute(
                "SELECT id, before_job_id, after_job_id, schema_version, summary_json, created_at "
                "FROM comparison_history ORDER BY id DESC LIMIT ?", (limit,)
            ).fetchall()
        items = []
        for row in rows:
            item = dict(row)
            item["summary"] = json.loads(item.pop("summary_json"))
            items.append(item)
        return items

    def get_comparison(self, comparison_id: int) -> dict | None:
        with connect(self.db_path) as db:
            row = db.execute("SELECT * FROM comparison_history WHERE id=?", (comparison_id,)).fetchone()
        if row is None:
            return None
        item = dict(row)
        item["summary"] = json.loads(item.pop("summary_json"))
        item["result"] = json.loads(item.pop("result_json"))
        return item

    def request_sqlmap_confirmation(self, finding_id: int, *, requested_by: str) -> int:
        """Persist a candidate sourced from an existing SQLi finding; never launch a scanner."""
        if not requested_by.strip() or len(requested_by) > 128:
            raise ValueError("requested_by must contain 1-128 characters")
        with connect(self.db_path) as db:
            db.execute("BEGIN IMMEDIATE")
            finding = db.execute("""SELECT f.*, t.authorized, t.url AS target_url FROM normalized_findings f
                                    JOIN targets t ON t.id=f.target_id WHERE f.id=?""", (finding_id,)).fetchone()
            if finding is None:
                raise ValueError("Candidate finding does not exist")
            if not finding["authorized"]:
                raise PermissionError("Target is not authorized")
            if finding["vuln_type"] != "sql_injection":
                raise ValueError("Finding is not an SQL injection candidate")
            from cybersec.sqlmap_gate import validate_candidate
            validate_candidate(finding["target_url"], finding["url"], finding["parameter"])
            cursor = db.execute("""INSERT INTO sqlmap_confirmations
                (finding_id, target_id, candidate_url, parameter, requested_by)
                VALUES (?, ?, ?, ?, ?)""", (finding_id, finding["target_id"], finding["url"], finding["parameter"], requested_by.strip()))
            return cursor.lastrowid

    def approve_sqlmap_confirmation(self, confirmation_id: int, *, approved_by: str) -> None:
        """Separate named reviewer must approve the immutable candidate snapshot."""
        if not approved_by.strip() or len(approved_by) > 128:
            raise ValueError("approved_by must contain 1-128 characters")
        with connect(self.db_path) as db:
            db.execute("BEGIN IMMEDIATE")
            row = db.execute("""SELECT c.*, t.authorized FROM sqlmap_confirmations c
                                JOIN targets t ON t.id=c.target_id WHERE c.id=?""", (confirmation_id,)).fetchone()
            if row is None or row["status"] != "pending":
                raise ValueError("Confirmation not pending")
            if not row["authorized"]:
                raise PermissionError("Target authorization revoked")
            if approved_by.strip() == row["requested_by"]:
                raise PermissionError("Requester cannot approve their own confirmation")
            db.execute("""UPDATE sqlmap_confirmations SET status='approved', approved_by=?,
                          approved_at=strftime('%Y-%m-%dT%H:%M:%fZ','now') WHERE id=?""", (approved_by.strip(), confirmation_id))

    def claim_sqlmap_confirmation(self, confirmation_id: int) -> dict:
        """Atomically consume a one-shot approval and recheck target, finding and scope."""
        from cybersec.sqlmap_gate import validate_candidate
        with connect(self.db_path) as db:
            db.execute("BEGIN IMMEDIATE")
            row = db.execute("""SELECT c.*, t.authorized, t.url AS target_url,
                                  f.url AS finding_url, f.parameter AS finding_parameter, f.vuln_type
                                  FROM sqlmap_confirmations c
                                  JOIN targets t ON t.id=c.target_id
                                  JOIN normalized_findings f ON f.id=c.finding_id AND f.target_id=c.target_id
                                  WHERE c.id=?""", (confirmation_id,)).fetchone()
            if row is None or row["status"] != "approved":
                raise PermissionError("No unused approval for this confirmation")
            if not row["authorized"]:
                raise PermissionError("Target authorization revoked")
            if row["candidate_url"] != row["finding_url"] or row["parameter"] != row["finding_parameter"]:
                raise PermissionError("Finding changed since approval")
            if row["vuln_type"] != "sql_injection":
                raise PermissionError("Candidate finding no longer qualifies")
            validate_candidate(row["target_url"], row["candidate_url"], row["parameter"])
            db.execute("""UPDATE sqlmap_confirmations SET status='claimed',
                          claimed_at=strftime('%Y-%m-%dT%H:%M:%fZ','now') WHERE id=?""", (confirmation_id,))
            return {"id": row["id"], "target_url": row["target_url"],
                    "candidate_url": row["candidate_url"], "parameter": row["parameter"],
                    "finding_id": row["finding_id"]}

    def finish_sqlmap_confirmation(self, confirmation_id: int, *, status: str, summary: str) -> None:
        if status not in {"completed", "failed"}:
            raise ValueError("Invalid completion status")
        with connect(self.db_path) as db:
            cur = db.execute("""UPDATE sqlmap_confirmations SET status=?, summary=?,
                          finished_at=strftime('%Y-%m-%dT%H:%M:%fZ','now')
                          WHERE id=? AND status='claimed'""", (status, summary[:500], confirmation_id))
            if cur.rowcount != 1:
                raise ValueError("Confirmation not claimed")

    def list_findings(self) -> list[Finding]:
        with connect(self.db_path) as db:
            rows = db.execute(
                "SELECT * FROM normalized_findings ORDER BY "
                "CASE severity WHEN 'Critical' THEN 0 WHEN 'High' THEN 1 WHEN 'Medium' THEN 2 "
                "WHEN 'Low' THEN 3 ELSE 4 END, id"
            ).fetchall()
        return [self._finding(r) for r in rows]

    def upsert_remediation_task(self, finding_id: int, *, status: str | None = None,
                                assignee: str | None = None, due_date: str | None = None,
                                notes: str | None = None) -> dict:
        """Create or update a remediation task for a stored finding."""
        from datetime import date
        allowed = {"open", "in_progress", "blocked", "resolved", "accepted"}
        with connect(self.db_path) as db:
            finding = db.execute("SELECT id FROM normalized_findings WHERE id = ?", (finding_id,)).fetchone()
            if finding is None:
                raise ValueError(f"Finding #{finding_id} does not exist.")
            existing = db.execute("SELECT * FROM remediation_tasks WHERE finding_id = ?", (finding_id,)).fetchone()
            new_status = str(status if status is not None else (existing["status"] if existing else "open")).strip().lower()
            if new_status not in allowed:
                raise ValueError("status must be open, in_progress, blocked, resolved, or accepted")
            new_assignee = str(assignee if assignee is not None else (existing["assignee"] if existing else "")).strip()
            new_notes = str(notes if notes is not None else (existing["notes"] if existing else "")).strip()
            if len(new_assignee) > 120:
                raise ValueError("assignee must be at most 120 characters")
            if len(new_notes) > 2000:
                raise ValueError("notes must be at most 2000 characters")
            if due_date is None:
                new_due_date = existing["due_date"] if existing else None
            else:
                new_due_date = str(due_date).strip() or None
                if new_due_date:
                    try:
                        if date.fromisoformat(new_due_date).isoformat() != new_due_date:
                            raise ValueError
                    except ValueError as exc:
                        raise ValueError("due_date must be a valid YYYY-MM-DD date or an empty string") from exc
            db.execute("""INSERT INTO remediation_tasks(finding_id,status,assignee,due_date,notes)
                VALUES(?,?,?,?,?) ON CONFLICT(finding_id) DO UPDATE SET status=excluded.status,
                assignee=excluded.assignee,due_date=excluded.due_date,notes=excluded.notes,
                updated_at=strftime('%Y-%m-%dT%H:%M:%fZ','now')""",
                (finding_id, new_status, new_assignee, new_due_date, new_notes))
            row = db.execute("SELECT * FROM remediation_tasks WHERE finding_id = ?", (finding_id,)).fetchone()
            db.execute("""INSERT INTO remediation_history(task_id,finding_id,event_type,old_status,new_status,
                old_assignee,new_assignee,old_due_date,new_due_date) VALUES(?,?,?,?,?,?,?,?,?)""",
                (row["id"], finding_id, "created" if existing is None else "updated",
                 existing["status"] if existing else None, new_status,
                 existing["assignee"] if existing else None, new_assignee,
                 existing["due_date"] if existing else None, new_due_date))
        return dict(row)

    def list_remediation_tasks(self, *, status: str | None = None, overdue_only: bool = False) -> list[dict]:
        """List tasks with finding and target context; no scanner activity is performed."""
        from datetime import date
        if status is not None and status not in {"open", "in_progress", "blocked", "resolved", "accepted"}:
            raise ValueError("status must be open, in_progress, blocked, resolved, or accepted")
        today = date.today().isoformat()
        sql = """SELECT rt.*, nf.title AS finding_title, nf.severity, nf.url AS finding_url,
            nf.recommendation, nf.target_id, t.url AS target_url
            FROM remediation_tasks rt JOIN normalized_findings nf ON nf.id=rt.finding_id
            JOIN targets t ON t.id=nf.target_id WHERE 1=1"""
        params: list[object] = []
        if status is not None:
            sql += " AND rt.status = ?"; params.append(status)
        if overdue_only:
            sql += " AND rt.due_date IS NOT NULL AND rt.due_date < ? AND rt.status NOT IN ('resolved','accepted')"; params.append(today)
        sql += " ORDER BY CASE rt.status WHEN 'blocked' THEN 0 WHEN 'open' THEN 1 WHEN 'in_progress' THEN 2 ELSE 3 END, rt.due_date IS NULL, rt.due_date, rt.id"
        with connect(self.db_path) as db:
            rows = [dict(row) for row in db.execute(sql, params).fetchall()]
            policies = {r["severity"]: int(r["days"]) for r in db.execute("SELECT severity, days FROM remediation_sla_policies")}
        from datetime import date, datetime, timedelta
        today_date = date.today()
        for item in rows:
            days = policies.get(item["severity"], 30)
            try:
                start = date.fromisoformat(str(item["created_at"])[:10])
            except ValueError:
                start = today_date
            sla_due = start + timedelta(days=days)
            item["sla_days"] = days
            item["sla_due_date"] = sla_due.isoformat()
            verification = self.latest_remediation_verification(int(item["id"]))
            item["verification_status"] = verification["outcome"] if verification else "unverified"
            item["verification_id"] = verification["id"] if verification else None
            item["sla_remaining_days"] = (sla_due - today_date).days
            if item["status"] in {"resolved", "accepted"}:
                item["sla_status"] = "closed_on_time" if str(item.get("updated_at", ""))[:10] <= sla_due.isoformat() else "closed_late"
            else:
                item["sla_status"] = "breached" if today_date > sla_due else ("due_soon" if (sla_due-today_date).days <= 3 else "within_sla")
        return rows

    def remediation_sla_policies(self) -> dict:
        with connect(self.db_path) as db:
            rows = db.execute("SELECT severity, days, updated_at FROM remediation_sla_policies ORDER BY CASE severity WHEN 'Critical' THEN 0 WHEN 'High' THEN 1 WHEN 'Medium' THEN 2 WHEN 'Low' THEN 3 ELSE 4 END").fetchall()
        return {r["severity"]: {"days": r["days"], "updated_at": r["updated_at"]} for r in rows}

    def set_remediation_sla_policy(self, severity: str, days: int) -> dict:
        severity = str(severity).strip().title()
        if severity not in {"Critical", "High", "Medium", "Low", "Info"}:
            raise ValueError("severity must be Critical, High, Medium, Low, or Info")
        if isinstance(days, bool) or not isinstance(days, int) or not 1 <= days <= 3650:
            raise ValueError("days must be an integer between 1 and 3650")
        with connect(self.db_path) as db:
            db.execute("INSERT INTO remediation_sla_policies(severity,days,updated_at) VALUES(?,?,strftime('%Y-%m-%dT%H:%M:%fZ','now')) ON CONFLICT(severity) DO UPDATE SET days=excluded.days,updated_at=strftime('%Y-%m-%dT%H:%M:%fZ','now')", (severity, days))
        return self.remediation_sla_policies()[severity]

    def remediation_history(self, task_id: int | None = None) -> list[dict]:
        sql = "SELECT * FROM remediation_history"
        params: tuple = ()
        if task_id is not None:
            sql += " WHERE task_id=?"; params = (task_id,)
        sql += " ORDER BY id DESC LIMIT 1000"
        with connect(self.db_path) as db:
            return [dict(r) for r in db.execute(sql, params).fetchall()]

    def remediation_sla_summary(self) -> dict:
        tasks = self.list_remediation_tasks()
        counts = {key: 0 for key in ("within_sla", "due_soon", "breached", "closed_on_time", "closed_late")}
        for task in tasks:
            counts[task["sla_status"]] = counts.get(task["sla_status"], 0) + 1
        active = [t for t in tasks if t["status"] not in {"resolved", "accepted"}]
        return {"total": len(tasks), "by_sla_status": counts, "active": len(active), "breached": counts["breached"], "policies": self.remediation_sla_policies()}

    def record_remediation_verification(self, task_id: int, *, outcome: str, evidence: str = "",
                                        notes: str = "", verified_by: str = "") -> dict:
        """Record an explicit verification decision for a remediation task."""
        outcome = str(outcome).strip().lower()
        if outcome not in {"verified", "rejected", "pending"}:
            raise ValueError("outcome must be verified, rejected, or pending")
        evidence, notes, verified_by = str(evidence).strip(), str(notes).strip(), str(verified_by).strip()
        if len(evidence) > 2000 or len(notes) > 2000 or len(verified_by) > 120:
            raise ValueError("evidence and notes must be at most 2000 characters; verified_by at most 120")
        with connect(self.db_path) as db:
            task = db.execute("SELECT id, status FROM remediation_tasks WHERE id=?", (task_id,)).fetchone()
            if task is None:
                raise ValueError(f"Remediation task #{task_id} does not exist.")
            db.execute("INSERT INTO remediation_verifications(task_id,outcome,evidence,notes,verified_by) VALUES(?,?,?,?,?)",
                       (task_id, outcome, evidence, notes, verified_by))
            row = db.execute("SELECT * FROM remediation_verifications WHERE id=last_insert_rowid()").fetchone()
        return dict(row)

    def remediation_verification_history(self, task_id: int) -> list[dict]:
        with connect(self.db_path) as db:
            if db.execute("SELECT 1 FROM remediation_tasks WHERE id=?", (task_id,)).fetchone() is None:
                raise ValueError(f"Remediation task #{task_id} does not exist.")
            return [dict(row) for row in db.execute(
                "SELECT * FROM remediation_verifications WHERE task_id=? ORDER BY id DESC LIMIT 100", (task_id,)
            ).fetchall()]

    def latest_remediation_verification(self, task_id: int) -> dict | None:
        with connect(self.db_path) as db:
            row = db.execute("SELECT * FROM remediation_verifications WHERE task_id=? ORDER BY id DESC LIMIT 1", (task_id,)).fetchone()
        return dict(row) if row else None

    def remediation_verification_summary(self) -> dict:
        with connect(self.db_path) as db:
            total = db.execute("SELECT COUNT(*) FROM remediation_tasks").fetchone()[0]
            verified = db.execute("SELECT COUNT(*) FROM (SELECT task_id,outcome,ROW_NUMBER() OVER (PARTITION BY task_id ORDER BY id DESC) rn FROM remediation_verifications) WHERE rn=1 AND outcome='verified'").fetchone()[0]
            rejected = db.execute("SELECT COUNT(*) FROM (SELECT task_id,outcome,ROW_NUMBER() OVER (PARTITION BY task_id ORDER BY id DESC) rn FROM remediation_verifications) WHERE rn=1 AND outcome='rejected'").fetchone()[0]
        return {"tasks": total, "verified": verified, "rejected_or_failed": rejected, "unverified": max(0, total-verified-rejected)}

    def remediation_metrics(self, *, start_date: str | None = None, end_date: str | None = None) -> dict:
        """Build deterministic remediation KPIs from stored task, audit and verification records.

        The date range applies to task creation for coverage/verification metrics and to
        resolution date for resolution-time/SLA metrics. Dates are inclusive ISO YYYY-MM-DD.
        """
        from datetime import date, datetime, timedelta
        from statistics import median

        def parse_date(value: str | None, label: str) -> date | None:
            if value in (None, ""):
                return None
            try:
                parsed = date.fromisoformat(str(value))
            except ValueError as exc:
                raise ValueError(f"{label} must be a valid YYYY-MM-DD date") from exc
            if parsed.isoformat() != value:
                raise ValueError(f"{label} must use YYYY-MM-DD format")
            return parsed

        start = parse_date(start_date, "start_date")
        end = parse_date(end_date, "end_date")
        if start and end and start > end:
            raise ValueError("start_date must be on or before end_date")
        with connect(self.db_path) as db:
            policies = {row["severity"]: int(row["days"]) for row in db.execute(
                "SELECT severity, days FROM remediation_sla_policies").fetchall()}
            rows = [dict(row) for row in db.execute("""
                SELECT rt.id AS task_id, rt.finding_id, rt.status, rt.assignee, rt.created_at,
                       rt.updated_at, nf.severity, nf.title AS finding_title, nf.target_id,
                       t.url AS target_url,
                       (SELECT MIN(rh.changed_at) FROM remediation_history rh
                         WHERE rh.task_id=rt.id AND rh.new_status='resolved') AS first_resolved_at,
                       (SELECT rv.outcome FROM remediation_verifications rv
                         WHERE rv.task_id=rt.id ORDER BY rv.id DESC LIMIT 1) AS latest_verification
                FROM remediation_tasks rt
                JOIN normalized_findings nf ON nf.id=rt.finding_id
                JOIN targets t ON t.id=nf.target_id
                ORDER BY rt.id
            """).fetchall()]

        def daypart(value: object) -> date | None:
            if not value:
                return None
            try:
                return date.fromisoformat(str(value)[:10])
            except ValueError:
                return None

        def in_range(value: object) -> bool:
            current = daypart(value)
            return current is not None and (start is None or current >= start) and (end is None or current <= end)

        task_rows: list[dict] = []
        for row in rows:
            created_day = daypart(row["created_at"])
            severity = row["severity"] or "Unknown"
            sla_days = policies.get(severity, 30)
            sla_due = created_day + timedelta(days=sla_days) if created_day else None
            resolved_at = row["first_resolved_at"]
            # For legacy tasks without audit events, updated_at is a conservative fallback.
            if row["status"] == "resolved" and not resolved_at:
                resolved_at = row["updated_at"]
            resolved_day = daypart(resolved_at) if row["status"] == "resolved" else None
            duration_days = None
            if row["status"] == "resolved" and created_day and resolved_day:
                duration_days = max(0, (resolved_day - created_day).days)
            resolved_in_period = row["status"] == "resolved" and in_range(resolved_at)
            task_rows.append({
                **row,
                "sla_days": sla_days,
                "sla_due_date": sla_due.isoformat() if sla_due else None,
                "resolved_at": resolved_at if row["status"] == "resolved" else None,
                "resolution_days": duration_days,
                "resolved_in_period": resolved_in_period,
                "sla_met": bool(resolved_in_period and sla_due and resolved_day and resolved_day <= sla_due),
            })

        created = [item for item in task_rows if in_range(item["created_at"])]
        resolved = [item for item in task_rows if item["resolved_in_period"]]
        durations = sorted(item["resolution_days"] for item in resolved if item["resolution_days"] is not None)
        sla_met = sum(1 for item in resolved if item["sla_met"])
        verified = sum(1 for item in created if item["latest_verification"] == "verified")

        def grouped(field: str, rows_to_group: list[dict]) -> list[dict]:
            groups: dict[str, list[dict]] = {}
            for item in rows_to_group:
                key = str(item.get(field) or "Unassigned")
                groups.setdefault(key, []).append(item)
            result = []
            for key in sorted(groups, key=str.casefold):
                group = groups[key]
                group_resolved = [item for item in group if item["resolved_in_period"]]
                group_durations = sorted(item["resolution_days"] for item in group_resolved if item["resolution_days"] is not None)
                group_sla_met = sum(1 for item in group_resolved if item["sla_met"])
                result.append({
                    "name": key,
                    "tasks_created": len(group),
                    "resolved_in_period": len(group_resolved),
                    "average_resolution_days": round(sum(group_durations) / len(group_durations), 2) if group_durations else None,
                    "median_resolution_days": median(group_durations) if group_durations else None,
                    "sla_compliance_percent": round(100 * group_sla_met / len(group_resolved), 2) if group_resolved else None,
                    "verified_tasks": sum(1 for item in group if item["latest_verification"] == "verified"),
                })
            return result

        return {
            "period": {"start_date": start.isoformat() if start else None, "end_date": end.isoformat() if end else None,
                       "date_basis": "task creation for verification coverage; resolution date for resolution and SLA metrics"},
            "summary": {
                "tasks_created": len(created),
                "resolved_in_period": len(resolved),
                "average_resolution_days": round(sum(durations) / len(durations), 2) if durations else None,
                "median_resolution_days": median(durations) if durations else None,
                "sla_compliance_percent": round(100 * sla_met / len(resolved), 2) if resolved else None,
                "verified_task_percent": round(100 * verified / len(created), 2) if created else None,
                "verified_tasks": verified,
                "tasks_with_latest_verification": sum(1 for item in created if item["latest_verification"] in {"verified", "rejected", "pending"}),
            },
            "by_severity": grouped("severity", created),
            "by_assignee": grouped("assignee", created),
            "by_target": grouped("target_url", created),
            "tasks": [{key: item[key] for key in (
                "task_id", "finding_id", "status", "severity", "finding_title", "target_id", "target_url",
                "assignee", "created_at", "resolved_at", "resolution_days", "sla_days", "sla_due_date",
                "sla_met", "latest_verification") } for item in created],
        }

    def remediation_trends(self, *, start_date: str | None = None, end_date: str | None = None) -> dict:
        """Return daily task flow and equal-length period-over-period remediation KPIs."""
        from datetime import date, timedelta
        import calendar

        base = self.remediation_metrics(start_date=start_date, end_date=end_date)
        start = date.fromisoformat(base["period"]["start_date"]) if base["period"]["start_date"] else None
        end = date.fromisoformat(base["period"]["end_date"]) if base["period"]["end_date"] else None
        if start is None and end is None:
            end = date.today()
            start = end - timedelta(days=29)
        elif start is None:
            start = end - timedelta(days=29)
        elif end is None:
            end = date.today()
        if start > end:
            raise ValueError("start_date must be on or before end_date")
        span = (end - start).days + 1
        previous_end = start - timedelta(days=1)
        previous_start = previous_end - timedelta(days=span - 1)
        previous = self.remediation_metrics(start_date=previous_start.isoformat(), end_date=previous_end.isoformat())
        with connect(self.db_path) as db:
            created_rows = db.execute("SELECT substr(created_at,1,10) day, COUNT(*) count FROM remediation_tasks WHERE substr(created_at,1,10) BETWEEN ? AND ? GROUP BY substr(created_at,1,10)", (start.isoformat(), end.isoformat())).fetchall()
            resolved_rows = db.execute("SELECT substr(changed_at,1,10) day, COUNT(DISTINCT task_id) count FROM remediation_history WHERE new_status='resolved' AND substr(changed_at,1,10) BETWEEN ? AND ? GROUP BY substr(changed_at,1,10)", (start.isoformat(), end.isoformat())).fetchall()
            open_rows = db.execute("SELECT status, COUNT(*) count FROM remediation_tasks WHERE status NOT IN ('resolved','accepted') AND created_at <= ? GROUP BY status", (end.isoformat()+'T23:59:59Z',)).fetchall()
        created_by_day = {r['day']: int(r['count']) for r in created_rows}
        resolved_by_day = {r['day']: int(r['count']) for r in resolved_rows}
        daily = []
        cursor = start
        while cursor <= end:
            day = cursor.isoformat()
            daily.append({"date": day, "created": created_by_day.get(day, 0), "resolved": resolved_by_day.get(day, 0)})
            cursor += timedelta(days=1)
        def delta(key):
            current = base['summary'].get(key)
            prior = previous['summary'].get(key)
            if current is None or prior is None:
                return {"current": current, "previous": prior, "absolute_change": None, "percent_change": None}
            absolute = round(current - prior, 2) if isinstance(current, (int, float)) and isinstance(prior, (int, float)) else None
            percent = round(100 * absolute / abs(prior), 2) if absolute is not None and prior != 0 else (0.0 if absolute == 0 else None)
            return {"current": current, "previous": prior, "absolute_change": absolute, "percent_change": percent}
        return {
            "period": {"start_date": start.isoformat(), "end_date": end.isoformat(), "days": span},
            "previous_period": {"start_date": previous_start.isoformat(), "end_date": previous_end.isoformat()},
            "daily": daily,
            "comparison": {key: delta(key) for key in ("tasks_created", "resolved_in_period", "average_resolution_days", "sla_compliance_percent", "verified_task_percent")},
            "current_open_tasks_by_status": {r['status']: int(r['count']) for r in open_rows},
            "current": base['summary'],
            "previous": previous['summary'],
        }

    def save_remediation_trend_snapshot(self, *, start_date: str | None = None, end_date: str | None = None) -> dict:
        import json
        report = self.remediation_trends(start_date=start_date, end_date=end_date)
        with connect(self.db_path) as db:
            db.execute("INSERT INTO remediation_trend_snapshots(start_date,end_date,report_json) VALUES(?,?,?)",
                       (report['period']['start_date'], report['period']['end_date'], json.dumps(report, sort_keys=True)))
            row = db.execute("SELECT * FROM remediation_trend_snapshots WHERE id=last_insert_rowid()").fetchone()
        return {"id": row['id'], "start_date": row['start_date'], "end_date": row['end_date'], "created_at": row['created_at'], "report": report}

    def list_remediation_trend_snapshots(self, limit: int = 100) -> list[dict]:
        import json
        if isinstance(limit, bool) or not isinstance(limit, int) or not 1 <= limit <= 500:
            raise ValueError("limit must be between 1 and 500")
        with connect(self.db_path) as db:
            rows = db.execute("SELECT id,start_date,end_date,created_at FROM remediation_trend_snapshots ORDER BY id DESC LIMIT ?", (limit,)).fetchall()
        return [dict(row) for row in rows]

    def get_remediation_trend_snapshot(self, snapshot_id: int) -> dict:
        import json
        with connect(self.db_path) as db:
            row = db.execute("SELECT * FROM remediation_trend_snapshots WHERE id=?", (snapshot_id,)).fetchone()
        if row is None:
            raise ValueError(f"Trend snapshot #{snapshot_id} does not exist.")
        return {"id": row['id'], "start_date": row['start_date'], "end_date": row['end_date'], "created_at": row['created_at'], "report": json.loads(row['report_json'])}

    def remediation_summary(self) -> dict:
        from datetime import date
        today = date.today().isoformat()
        with connect(self.db_path) as db:
            rows = db.execute("SELECT status, COUNT(*) AS count FROM remediation_tasks GROUP BY status").fetchall()
            overdue = db.execute("SELECT COUNT(*) FROM remediation_tasks WHERE due_date IS NOT NULL AND due_date < ? AND status NOT IN ('resolved','accepted')", (today,)).fetchone()[0]
            total = db.execute("SELECT COUNT(*) FROM remediation_tasks").fetchone()[0]
        counts = {key: 0 for key in ("open", "in_progress", "blocked", "resolved", "accepted")}
        counts.update({row["status"]: row["count"] for row in rows})
        return {"total": total, "by_status": counts, "overdue": overdue}

    _RISK_INTELLIGENCE_DEFAULTS = {"window_days": 7, "minimum_findings": 3, "growth_ratio": 1.5, "criticality_boost": True}

    def get_risk_intelligence_config(self) -> dict:
        with connect(self.db_path) as db:
            row = db.execute("SELECT config_json, updated_at FROM risk_intelligence_config WHERE id=1").fetchone()
        config = dict(self._RISK_INTELLIGENCE_DEFAULTS)
        if row:
            config.update(json.loads(row["config_json"]))
        return {**config, "updated_at": row["updated_at"] if row else None}

    def set_risk_intelligence_config(self, values: dict) -> dict:
        if not isinstance(values, dict):
            raise ValueError("Configuration must be a JSON object")
        allowed = set(self._RISK_INTELLIGENCE_DEFAULTS)
        unknown = set(values) - allowed
        if unknown:
            raise ValueError("Unknown configuration fields: " + ", ".join(sorted(unknown)))
        current = {key: value for key, value in self.get_risk_intelligence_config().items() if key in allowed}
        candidate = {**current, **values}
        window = candidate["window_days"]
        minimum = candidate["minimum_findings"]
        ratio = candidate["growth_ratio"]
        boost = candidate["criticality_boost"]
        if isinstance(window, bool) or not isinstance(window, int) or not 1 <= window <= 90:
            raise ValueError("window_days must be an integer between 1 and 90")
        if isinstance(minimum, bool) or not isinstance(minimum, int) or not 1 <= minimum <= 10000:
            raise ValueError("minimum_findings must be an integer between 1 and 10000")
        if isinstance(ratio, bool) or not isinstance(ratio, (int, float)) or not 1.0 <= float(ratio) <= 100.0:
            raise ValueError("growth_ratio must be between 1 and 100")
        if not isinstance(boost, bool):
            raise ValueError("criticality_boost must be a boolean")
        candidate["growth_ratio"] = float(ratio)
        with connect(self.db_path) as db:
            db.execute("INSERT INTO risk_intelligence_config(id, config_json) VALUES(1, ?) ON CONFLICT(id) DO UPDATE SET config_json=excluded.config_json, updated_at=strftime('%Y-%m-%dT%H:%M:%fZ','now')", (json.dumps(candidate, sort_keys=True),))
        return self.get_risk_intelligence_config()

    def _validate_risk_rule_config(self, values: dict, base: dict | None = None) -> dict:
        if not isinstance(values, dict):
            raise ValueError("Rule config must be a JSON object")
        allowed = set(self._RISK_INTELLIGENCE_DEFAULTS)
        unknown = set(values) - allowed
        if unknown:
            raise ValueError("Unknown configuration fields: " + ", ".join(sorted(unknown)))
        candidate = {**(base or self._RISK_INTELLIGENCE_DEFAULTS), **values}
        window, minimum, ratio, boost = (candidate[k] for k in ("window_days", "minimum_findings", "growth_ratio", "criticality_boost"))
        if isinstance(window, bool) or not isinstance(window, int) or not 1 <= window <= 90:
            raise ValueError("window_days must be an integer between 1 and 90")
        if isinstance(minimum, bool) or not isinstance(minimum, int) or not 1 <= minimum <= 10000:
            raise ValueError("minimum_findings must be an integer between 1 and 10000")
        if isinstance(ratio, bool) or not isinstance(ratio, (int, float)) or not 1.0 <= float(ratio) <= 100.0:
            raise ValueError("growth_ratio must be between 1 and 100")
        if not isinstance(boost, bool):
            raise ValueError("criticality_boost must be a boolean")
        candidate["growth_ratio"] = float(ratio)
        return candidate

    @staticmethod
    def _risk_rule_actor(actor: object) -> str:
        value = str(actor or "").strip()
        if not value or len(value) > 120:
            raise ValueError("actor must contain 1 to 120 characters")
        return value

    @staticmethod
    def _risk_rule_snapshot(name: str, description: str, config: dict, enabled: bool) -> dict:
        return {"name": name, "description": description, "config": config, "enabled": bool(enabled)}

    @staticmethod
    def _record_risk_rule_version(db, rule_id: int, snapshot: dict, actor: str) -> int:
        row = db.execute("SELECT COALESCE(MAX(version_number), 0) + 1 AS next_version FROM risk_intelligence_rule_versions WHERE rule_id=?", (rule_id,)).fetchone()
        version = int(row["next_version"])
        db.execute("INSERT INTO risk_intelligence_rule_versions(rule_id,version_number,snapshot_json,actor) VALUES(?,?,?,?)", (rule_id, version, json.dumps(snapshot, sort_keys=True), actor))
        db.execute("INSERT INTO risk_intelligence_rule_governance(rule_id,active_version_number) VALUES(?,?) ON CONFLICT(rule_id) DO UPDATE SET active_version_number=excluded.active_version_number, updated_at=strftime('%Y-%m-%dT%H:%M:%fZ','now')", (rule_id, version))
        return version

    def list_risk_intelligence_rule_versions(self, rule_id: int) -> dict:
        self.get_risk_intelligence_rule(rule_id)
        with connect(self.db_path) as db:
            rows = db.execute("SELECT id,rule_id,version_number,snapshot_json,actor,created_at FROM risk_intelligence_rule_versions WHERE rule_id=? ORDER BY version_number DESC", (rule_id,)).fetchall()
        items = []
        for row in rows:
            item = dict(row)
            item["snapshot"] = json.loads(item.pop("snapshot_json"))
            items.append(item)
        return {"rule_id": rule_id, "items": items, "total": len(items)}

    def rollback_risk_intelligence_rule(self, rule_id: int, version_number: int, actor: str = "analyst") -> dict:
        if isinstance(version_number, bool) or not isinstance(version_number, int) or version_number < 1:
            raise ValueError("version_number must be a positive integer")
        actor = self._risk_rule_actor(actor)
        with connect(self.db_path) as db:
            row = db.execute("SELECT snapshot_json FROM risk_intelligence_rule_versions WHERE rule_id=? AND version_number=?", (rule_id, version_number)).fetchone()
            previous_latest = db.execute("SELECT COALESCE(MAX(version_number),0) AS version FROM risk_intelligence_rule_versions WHERE rule_id=?", (rule_id,)).fetchone()["version"]
        if row is None:
            self.get_risk_intelligence_rule(rule_id)
            raise ValueError(f"Version {version_number} does not exist for risk rule #{rule_id}.")
        snapshot = json.loads(row["snapshot_json"])
        restored = self.save_risk_intelligence_rule({"id": rule_id, **snapshot, "actor": actor})
        with connect(self.db_path) as db:
            latest = db.execute("SELECT COALESCE(MAX(version_number),0) AS version FROM risk_intelligence_rule_versions WHERE rule_id=?", (rule_id,)).fetchone()["version"]
            if latest == previous_latest:
                latest = self._record_risk_rule_version(db, rule_id, snapshot, actor)
            db.execute("INSERT INTO risk_intelligence_rule_audit(rule_id,action,actor,before_json,after_json) VALUES(?,?,?,?,?)", (rule_id, "rolled_back", actor, json.dumps({"restored_version": version_number}), json.dumps({"current_version": latest, "restored_snapshot": snapshot}, sort_keys=True)))
        restored["restored_from_version"] = version_number
        restored["current_version"] = int(latest)
        return restored

    def list_risk_intelligence_comparison_history(self, limit: int = 50) -> dict:
        if isinstance(limit, bool) or not isinstance(limit, int) or not 1 <= limit <= 200:
            raise ValueError("limit must be between 1 and 200")
        with connect(self.db_path) as db:
            rows = db.execute("SELECT id,rule_ids_json,summary_json,created_by,created_at FROM risk_intelligence_comparison_history ORDER BY id DESC LIMIT ?", (limit,)).fetchall()
        items = []
        for row in rows:
            item = dict(row)
            item["rule_ids"] = json.loads(item.pop("rule_ids_json"))
            item["summary"] = json.loads(item.pop("summary_json"))
            items.append(item)
        return {"items": items, "total": len(items), "limit": limit}

    def get_risk_intelligence_comparison(self, comparison_id: int) -> dict:
        if isinstance(comparison_id, bool) or not isinstance(comparison_id, int) or comparison_id < 1:
            raise ValueError("comparison_id must be a positive integer")
        with connect(self.db_path) as db:
            row = db.execute("SELECT * FROM risk_intelligence_comparison_history WHERE id=?", (comparison_id,)).fetchone()
        if row is None:
            raise ValueError(f"Risk comparison #{comparison_id} does not exist.")
        item = dict(row)
        item["rule_ids"] = json.loads(item.pop("rule_ids_json"))
        item["summary"] = json.loads(item.pop("summary_json"))
        item["result"] = json.loads(item.pop("result_json"))
        return item

    def list_risk_intelligence_rules(self, *, include_audit: bool = False) -> dict:
        with connect(self.db_path) as db:
            rows = db.execute("SELECT * FROM risk_intelligence_rules ORDER BY id").fetchall()
            audit_rows = db.execute("SELECT * FROM risk_intelligence_rule_audit ORDER BY id DESC LIMIT 200").fetchall() if include_audit else []
        rules = []
        for row in rows:
            item = dict(row)
            item["config"] = json.loads(item.pop("config_json"))
            item["enabled"] = bool(item["enabled"])
            rules.append(item)
        audit = []
        for row in audit_rows:
            item = dict(row)
            item["before"] = json.loads(item.pop("before_json")) if item.get("before_json") else None
            item["after"] = json.loads(item.pop("after_json"))
            audit.append(item)
        return {"items": rules, "total": len(rules), "audit": audit if include_audit else None}

    def save_risk_intelligence_rule(self, values: dict) -> dict:
        if not isinstance(values, dict):
            raise ValueError("Rule must be a JSON object")
        allowed = {"id", "name", "description", "config", "enabled", "actor"}
        unknown = set(values) - allowed
        if unknown:
            raise ValueError("Unknown rule fields: " + ", ".join(sorted(unknown)))
        name = str(values.get("name", "")).strip()
        description = str(values.get("description", "")).strip()
        actor = self._risk_rule_actor(values.get("actor", "analyst"))
        if not name or len(name) > 120:
            raise ValueError("name must contain 1 to 120 characters")
        if len(description) > 1000:
            raise ValueError("description must be at most 1000 characters")
        rule_id = values.get("id")
        if rule_id is not None and (isinstance(rule_id, bool) or not isinstance(rule_id, int) or rule_id < 1):
            raise ValueError("id must be a positive integer")
        enabled = values.get("enabled", True)
        if not isinstance(enabled, bool):
            raise ValueError("enabled must be a boolean")
        if rule_id is None:
            config = self._validate_risk_rule_config(values.get("config", {}))
            with connect(self.db_path) as db:
                try:
                    cursor = db.execute("INSERT INTO risk_intelligence_rules(name,description,config_json,enabled,created_by,updated_by) VALUES(?,?,?,?,?,?)", (name, description, json.dumps(config, sort_keys=True), int(enabled), actor, actor))
                except sqlite3.IntegrityError as exc:
                    raise ValueError("A rule with this name already exists") from exc
                new_id = int(cursor.lastrowid)
                after = {"name": name, "description": description, "config": config, "enabled": enabled}
                db.execute("INSERT INTO risk_intelligence_rule_audit(rule_id,action,actor,before_json,after_json) VALUES(?,?,?,?,?)", (new_id, "created", actor, None, json.dumps(after, sort_keys=True)))
                self._record_risk_rule_version(db, new_id, after, actor)
            return self.get_risk_intelligence_rule(new_id)
        with connect(self.db_path) as db:
            row = db.execute("SELECT * FROM risk_intelligence_rules WHERE id=?", (rule_id,)).fetchone()
            if row is None:
                raise ValueError(f"Risk rule #{rule_id} does not exist.")
            governance = db.execute("SELECT locked FROM risk_intelligence_rule_governance WHERE rule_id=?", (rule_id,)).fetchone()
            if governance and governance["locked"]:
                raise PermissionError(f"Risk rule #{rule_id} is locked by governance; unlock it before modifying.")
            if "enabled" not in values:
                enabled = bool(row["enabled"])
            old_config = json.loads(row["config_json"])
            config = self._validate_risk_rule_config(values.get("config", {}), old_config)
            before = {"name": row["name"], "description": row["description"], "config": old_config, "enabled": bool(row["enabled"])}
            after = {"name": name, "description": description, "config": config, "enabled": enabled}
            try:
                db.execute("UPDATE risk_intelligence_rules SET name=?,description=?,config_json=?,enabled=?,updated_by=?,updated_at=strftime('%Y-%m-%dT%H:%M:%fZ','now') WHERE id=?", (name, description, json.dumps(config, sort_keys=True), int(enabled), actor, rule_id))
            except sqlite3.IntegrityError as exc:
                raise ValueError("A rule with this name already exists") from exc
            action = "enabled" if not before["enabled"] and enabled else "disabled" if before["enabled"] and not enabled else "updated"
            db.execute("INSERT INTO risk_intelligence_rule_audit(rule_id,action,actor,before_json,after_json) VALUES(?,?,?,?,?)", (rule_id, action, actor, json.dumps(before, sort_keys=True), json.dumps(after, sort_keys=True)))
            if before != after:
                self._record_risk_rule_version(db, rule_id, after, actor)
        return self.get_risk_intelligence_rule(rule_id)

    def get_risk_intelligence_rule(self, rule_id: int) -> dict:
        with connect(self.db_path) as db:
            row = db.execute("SELECT * FROM risk_intelligence_rules WHERE id=?", (rule_id,)).fetchone()
        if row is None:
            raise ValueError(f"Risk rule #{rule_id} does not exist.")
        item = dict(row)
        item["config"] = json.loads(item.pop("config_json"))
        item["enabled"] = bool(item["enabled"])
        return item

    def set_risk_intelligence_rule_enabled(self, rule_id: int, enabled: bool, actor: str = "analyst") -> dict:
        if not isinstance(enabled, bool):
            raise ValueError("enabled must be a boolean")
        rule = self.get_risk_intelligence_rule(rule_id)
        if rule["enabled"] == enabled:
            return rule
        return self.save_risk_intelligence_rule({"id": rule_id, "name": rule["name"], "description": rule["description"], "config": rule["config"], "enabled": enabled, "actor": actor})

    def get_risk_intelligence_governance(self, rule_id: int) -> dict:
        self.get_risk_intelligence_rule(rule_id)
        with connect(self.db_path) as db:
            row = db.execute("SELECT * FROM risk_intelligence_rule_governance WHERE rule_id=?", (rule_id,)).fetchone()
        return dict(row) if row else {"rule_id": rule_id, "active_version_number": 1, "approved_version_number": None, "approved_by": None, "approved_at": None, "locked": 0, "updated_at": None}

    def set_risk_intelligence_active_version(self, rule_id: int, version_number: int, actor: str = "analyst") -> dict:
        actor = self._risk_rule_actor(actor)
        if isinstance(version_number, bool) or not isinstance(version_number, int) or version_number < 1:
            raise ValueError("version_number must be a positive integer")
        self.get_risk_intelligence_rule(rule_id)
        with connect(self.db_path) as db:
            version = db.execute("SELECT snapshot_json FROM risk_intelligence_rule_versions WHERE rule_id=? AND version_number=?", (rule_id, version_number)).fetchone()
            if not version: raise ValueError(f"Version {version_number} does not exist for risk rule #{rule_id}.")
            state = db.execute("SELECT locked FROM risk_intelligence_rule_governance WHERE rule_id=?", (rule_id,)).fetchone()
            if state and state["locked"]: raise PermissionError("Rule is locked; unlock it before changing the active version.")
            snapshot=json.loads(version["snapshot_json"])
            db.execute("UPDATE risk_intelligence_rules SET name=?,description=?,config_json=?,enabled=?,updated_by=?,updated_at=strftime('%Y-%m-%dT%H:%M:%fZ','now') WHERE id=?", (snapshot["name"],snapshot["description"],json.dumps(snapshot["config"],sort_keys=True),int(snapshot["enabled"]),actor,rule_id))
            db.execute("INSERT INTO risk_intelligence_rule_governance(rule_id,active_version_number) VALUES(?,?) ON CONFLICT(rule_id) DO UPDATE SET active_version_number=excluded.active_version_number,updated_at=strftime('%Y-%m-%dT%H:%M:%fZ','now')", (rule_id, version_number))
            db.execute("INSERT INTO risk_intelligence_governance_audit(rule_id,action,actor,details_json) VALUES(?,?,?,?)", (rule_id,"active_version_set",actor,json.dumps({"version_number":version_number,"snapshot_applied":True})))
        return self.get_risk_intelligence_governance(rule_id)

    def approve_risk_intelligence_rule(self, rule_id: int, actor: str = "approver", *, lock: bool = True) -> dict:
        actor = self._risk_rule_actor(actor)
        if not isinstance(lock, bool): raise ValueError("lock must be a boolean")
        rule = self.get_risk_intelligence_rule(rule_id)
        state = self.get_risk_intelligence_governance(rule_id)
        active = state["active_version_number"]
        with connect(self.db_path) as db:
            db.execute("UPDATE risk_intelligence_rule_governance SET approved_version_number=?,approved_by=?,approved_at=strftime('%Y-%m-%dT%H:%M:%fZ','now'),locked=?,updated_at=strftime('%Y-%m-%dT%H:%M:%fZ','now') WHERE rule_id=?", (active,actor,int(lock),rule_id))
            db.execute("INSERT INTO risk_intelligence_governance_audit(rule_id,action,actor,details_json) VALUES(?,?,?,?)", (rule_id,"approved",actor,json.dumps({"approved_version_number":active,"locked":lock,"rule_name":rule["name"]},sort_keys=True)))
        return self.get_risk_intelligence_governance(rule_id)

    def unlock_risk_intelligence_rule(self, rule_id: int, actor: str = "approver", reason: str = "") -> dict:
        actor = self._risk_rule_actor(actor)
        reason = str(reason).strip()
        if len(reason)>500: raise ValueError("reason must be at most 500 characters")
        self.get_risk_intelligence_rule(rule_id)
        with connect(self.db_path) as db:
            db.execute("INSERT INTO risk_intelligence_rule_governance(rule_id,active_version_number,locked) VALUES(?,1,0) ON CONFLICT(rule_id) DO UPDATE SET locked=0,updated_at=strftime('%Y-%m-%dT%H:%M:%fZ','now')", (rule_id,))
            db.execute("INSERT INTO risk_intelligence_governance_audit(rule_id,action,actor,details_json) VALUES(?,?,?,?)", (rule_id,"unlocked",actor,json.dumps({"reason":reason},sort_keys=True)))
        return self.get_risk_intelligence_governance(rule_id)

    def list_risk_intelligence_governance_audit(self, rule_id: int, limit: int = 100) -> dict:
        self.get_risk_intelligence_rule(rule_id)
        if isinstance(limit,bool) or not isinstance(limit,int) or not 1<=limit<=500: raise ValueError("limit must be between 1 and 500")
        with connect(self.db_path) as db: rows=db.execute("SELECT * FROM risk_intelligence_governance_audit WHERE rule_id=? ORDER BY id DESC LIMIT ?",(rule_id,limit)).fetchall()
        items=[]
        for row in rows:
            item=dict(row); item["details"]=json.loads(item.pop("details_json")); items.append(item)
        return {"rule_id":rule_id,"items":items,"total":len(items)}

    @staticmethod
    def _risk_rule_snapshot_from_record(rule: dict) -> dict:
        return {"name": rule["name"], "description": rule["description"], "config": rule["config"], "enabled": bool(rule["enabled"])}

    def get_risk_intelligence_policy_status(self) -> dict:
        """Inspect rule approval, active-version alignment, and live configuration drift."""
        rules = self.list_risk_intelligence_rules()["items"]
        items = []
        for rule in rules:
            state = self.get_risk_intelligence_governance(rule["id"])
            versions = self.list_risk_intelligence_rule_versions(rule["id"])["items"]
            snapshots = {item["version_number"]: item["snapshot"] for item in versions}
            active = state.get("active_version_number")
            active_snapshot = snapshots.get(active)
            live_snapshot = self._risk_rule_snapshot_from_record(rule)
            drift = active_snapshot is None or active_snapshot != live_snapshot
            approved = state.get("approved_version_number")
            approved_current = approved is not None and approved == active and not drift
            enabled = bool(rule["enabled"])
            if not enabled:
                status = "disabled"
            elif approved is None:
                status = "unapproved"
            elif approved != active:
                status = "approval_stale"
            elif drift:
                status = "configuration_drift"
            else:
                status = "compliant"
            items.append({"rule_id": rule["id"], "name": rule["name"], "enabled": enabled,
                          "active_version_number": active, "approved_version_number": approved,
                          "approved_by": state.get("approved_by"), "locked": bool(state.get("locked")),
                          "configuration_drift": drift, "approved_current_version": approved_current,
                          "status": status, "eligible_for_policy_evaluation": enabled and approved_current})
        counts = {key: sum(1 for item in items if item["status"] == key) for key in ("compliant", "disabled", "unapproved", "approval_stale", "configuration_drift")}
        return {"policy": "approved-active-version-only", "enforcement": "strict", "items": items, "total": len(items),
                "eligible": sum(1 for item in items if item["eligible_for_policy_evaluation"]), "counts": counts,
                "note": "Only enabled rules whose active version is still approved and whose live configuration matches its immutable snapshot are eligible. Status inspection is read-only."}

    def evaluate_risk_intelligence_policy(self, actor: str = "policy-engine") -> dict:
        """Preview only eligible approved rules, and persist an auditable evaluation summary."""
        actor = self._risk_rule_actor(actor)
        status = self.get_risk_intelligence_policy_status()
        results = []
        for item in status["items"]:
            if not item["eligible_for_policy_evaluation"]:
                continue
            rule = self.get_risk_intelligence_rule(item["rule_id"])
            preview = self.refresh_risk_intelligence(rule["config"], persist=False)
            signals = preview["items"]
            results.append({"rule_id": rule["id"], "name": rule["name"],
                            "active_version_number": item["active_version_number"],
                            "approved_version_number": item["approved_version_number"],
                            "total_signals": len(signals),
                            "by_severity": {severity: sum(1 for signal in signals if signal.get("severity") == severity) for severity in ("critical", "high", "warning", "info")}})
        summary = {"rules_total": status["total"], "rules_eligible": status["eligible"],
                   "rules_evaluated": len(results), "rules_excluded": status["total"] - len(results),
                   "total_signals": sum(item["total_signals"] for item in results), "policy_counts": status["counts"]}
        result = {"policy": status["policy"], "enforcement": status["enforcement"], "summary": summary,
                  "rule_results": results, "excluded_rules": [item for item in status["items"] if not item["eligible_for_policy_evaluation"]],
                  "note": "Evaluation uses stored local metadata only and is preview-only: no alerts are persisted, scanners are not run, and no outbound requests are made."}
        with connect(self.db_path) as db:
            cursor = db.execute("INSERT INTO risk_intelligence_policy_evaluations(evaluated_by,summary_json,result_json) VALUES(?,?,?)",
                                (actor, json.dumps(summary, sort_keys=True), json.dumps(result, sort_keys=True)))
            evaluation_id = int(cursor.lastrowid)
        return {"id": evaluation_id, "evaluated_by": actor, **result}

    def list_risk_intelligence_policy_evaluations(self, limit: int = 50) -> dict:
        if isinstance(limit, bool) or not isinstance(limit, int) or not 1 <= limit <= 200:
            raise ValueError("limit must be between 1 and 200")
        with connect(self.db_path) as db:
            rows = db.execute("SELECT id,evaluated_by,summary_json,created_at FROM risk_intelligence_policy_evaluations ORDER BY id DESC LIMIT ?", (limit,)).fetchall()
        items = []
        for row in rows:
            item = dict(row)
            item["summary"] = json.loads(item.pop("summary_json"))
            items.append(item)
        return {"items": items, "total": len(items), "limit": limit}

    def get_risk_intelligence_policy_evaluation(self, evaluation_id: int) -> dict:
        if isinstance(evaluation_id, bool) or not isinstance(evaluation_id, int) or evaluation_id < 1:
            raise ValueError("evaluation_id must be a positive integer")
        with connect(self.db_path) as db:
            row = db.execute("SELECT * FROM risk_intelligence_policy_evaluations WHERE id=?", (evaluation_id,)).fetchone()
        if row is None:
            raise ValueError(f"Risk policy evaluation #{evaluation_id} does not exist.")
        item = dict(row)
        item["summary"] = json.loads(item.pop("summary_json"))
        item["result"] = json.loads(item.pop("result_json"))
        return item

    @staticmethod
    def _redact_policy_evidence(value):
        """Redact common secret-bearing keys before evidence is persisted or exported."""
        sensitive = {"token", "access_token", "refresh_token", "password", "passwd", "secret",
                     "client_secret", "authorization", "api_key", "apikey", "private_key", "credential"}
        if isinstance(value, dict):
            return {str(key): ("[REDACTED]" if str(key).lower().replace("-", "_") in sensitive
                               or any(part in str(key).lower() for part in ("password", "secret", "token", "credential"))
                               else Repository._redact_policy_evidence(item)) for key, item in value.items()}
        if isinstance(value, list):
            return [Repository._redact_policy_evidence(item) for item in value]
        if isinstance(value, tuple):
            return [Repository._redact_policy_evidence(item) for item in value]
        return value

    def create_risk_policy_evidence(self, evaluation_id: int, actor: str = "compliance-analyst") -> dict:
        """Freeze a reproducible, secret-redacted compliance snapshot for an existing evaluation."""
        if isinstance(evaluation_id, bool) or not isinstance(evaluation_id, int) or evaluation_id < 1:
            raise ValueError("evaluation_id must be a positive integer")
        actor = self._risk_rule_actor(actor)
        evaluation = self.get_risk_intelligence_policy_evaluation(evaluation_id)
        result = evaluation["result"]
        rule_versions = []
        for item in result.get("rule_results", []):
            rule_versions.append({"rule_id": item.get("rule_id"), "name": item.get("name"),
                                 "active_version_number": item.get("active_version_number"),
                                 "approved_version_number": item.get("approved_version_number")})
        for item in result.get("excluded_rules", []):
            rule_versions.append({"rule_id": item.get("rule_id"), "name": item.get("name"),
                                 "active_version_number": item.get("active_version_number"),
                                 "approved_version_number": item.get("approved_version_number"),
                                 "excluded_status": item.get("status")})
        snapshot = self._redact_policy_evidence({
            "schema_version": 1,
            "evidence_type": "risk-policy-compliance",
            "evaluation": {"id": evaluation["id"], "evaluated_by": evaluation["evaluated_by"],
                           "created_at": evaluation["created_at"], "summary": evaluation["summary"]},
            "policy": {"name": result.get("policy"), "enforcement": result.get("enforcement"),
                       "summary": result.get("summary"), "rule_results": result.get("rule_results", []),
                       "excluded_rules": result.get("excluded_rules", [])},
            "rule_versions": sorted(rule_versions, key=lambda row: (row.get("rule_id") or 0, row.get("active_version_number") or 0)),
            "limitations": "Snapshot records a local metadata-only preview; it is not proof of external scanning or runtime enforcement."
        })
        canonical = json.dumps(snapshot, ensure_ascii=False, sort_keys=True, separators=(",", ":"))
        digest = hashlib.sha256(canonical.encode("utf-8")).hexdigest()
        with connect(self.db_path) as db:
            cursor = db.execute("INSERT INTO risk_policy_evidence(evaluation_id,created_by,snapshot_json,sha256) VALUES(?,?,?,?)",
                                (evaluation_id, actor, canonical, digest))
            evidence_id = int(cursor.lastrowid)
        return self.get_risk_policy_evidence(evidence_id)

    def list_risk_policy_evidence(self, limit: int = 50, evaluation_id: int | None = None) -> dict:
        if isinstance(limit, bool) or not isinstance(limit, int) or not 1 <= limit <= 200:
            raise ValueError("limit must be between 1 and 200")
        if evaluation_id is not None and (isinstance(evaluation_id, bool) or not isinstance(evaluation_id, int) or evaluation_id < 1):
            raise ValueError("evaluation_id must be a positive integer")
        with connect(self.db_path) as db:
            if evaluation_id is None:
                rows = db.execute("SELECT id,evaluation_id,created_by,sha256,created_at FROM risk_policy_evidence ORDER BY id DESC LIMIT ?", (limit,)).fetchall()
            else:
                rows = db.execute("SELECT id,evaluation_id,created_by,sha256,created_at FROM risk_policy_evidence WHERE evaluation_id=? ORDER BY id DESC LIMIT ?", (evaluation_id, limit)).fetchall()
        return {"items": [dict(row) for row in rows], "total": len(rows), "limit": limit}

    def get_risk_policy_evidence(self, evidence_id: int) -> dict:
        if isinstance(evidence_id, bool) or not isinstance(evidence_id, int) or evidence_id < 1:
            raise ValueError("evidence_id must be a positive integer")
        with connect(self.db_path) as db:
            row = db.execute("SELECT * FROM risk_policy_evidence WHERE id=?", (evidence_id,)).fetchone()
        if row is None:
            raise ValueError(f"Risk policy evidence #{evidence_id} does not exist.")
        item = dict(row)
        item["snapshot"] = json.loads(item.pop("snapshot_json"))
        canonical = json.dumps(item["snapshot"], ensure_ascii=False, sort_keys=True, separators=(",", ":"))
        item["integrity_valid"] = hashlib.sha256(canonical.encode("utf-8")).hexdigest() == item["sha256"]
        return item

    def verify_risk_policy_evidence(self, evidence_id: int) -> dict:
        item = self.get_risk_policy_evidence(evidence_id)
        return {"id": item["id"], "evaluation_id": item["evaluation_id"], "sha256": item["sha256"],
                "integrity_valid": item["integrity_valid"], "created_at": item["created_at"]}

    def export_risk_policy_compliance_report(self, evidence_id: int, format: str = "json") -> dict:
        evidence = self.get_risk_policy_evidence(evidence_id)
        if not evidence["integrity_valid"]:
            raise ValueError("Evidence integrity check failed; refusing to export report")
        fmt = str(format).strip().lower()
        if fmt not in {"json", "csv"}:
            raise ValueError("format must be json or csv")
        if fmt == "json":
            return {"format": "json", "filename": f"risk-policy-compliance-{evidence_id}.json", "sha256": evidence["sha256"], "report": evidence["snapshot"]}
        rows = []
        for rule in evidence["snapshot"].get("rule_versions", []):
            rows.append({"evidence_id": evidence_id, "evaluation_id": evidence["evaluation_id"],
                         "rule_id": rule.get("rule_id"), "name": rule.get("name"),
                         "active_version_number": rule.get("active_version_number"),
                         "approved_version_number": rule.get("approved_version_number"),
                         "excluded_status": rule.get("excluded_status", "")})
        return {"format": "csv", "filename": f"risk-policy-compliance-{evidence_id}.csv", "sha256": evidence["sha256"], "columns": ["evidence_id", "evaluation_id", "rule_id", "name", "active_version_number", "approved_version_number", "excluded_status"], "rows": rows}

    @staticmethod
    def _canonical_policy_bundle(value: dict) -> bytes:
        return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode("utf-8")

    @staticmethod
    def _policy_bundle_signing_key(signing_key):
        if signing_key is None:
            return None
        if not isinstance(signing_key, str) or len(signing_key.encode("utf-8")) < 16:
            raise ValueError("signing_key must contain at least 16 UTF-8 bytes")
        return signing_key.encode("utf-8")

    @staticmethod
    def _decode_ed25519_key(value: str, label: str) -> bytes:
        import base64
        if not isinstance(value, str) or not value.strip():
            raise ValueError(f"{label} must be base64-encoded raw Ed25519 key bytes")
        try:
            decoded = base64.b64decode(value.strip(), validate=True)
        except Exception as exc:
            raise ValueError(f"{label} must be valid base64") from exc
        if len(decoded) != 32:
            raise ValueError(f"{label} must decode to exactly 32 bytes")
        return decoded

    @staticmethod
    def _validate_evidence_key_id(key_id: str) -> str:
        value = str(key_id or "").strip()
        if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._-]{0,99}", value):
            raise ValueError("key_id must be 1..100 characters using letters, digits, dot, underscore, or hyphen")
        return value

    def register_risk_policy_evidence_signing_key(self, key_id: str, public_key_b64: str, actor: str = "security-admin") -> dict:
        """Register a trusted Ed25519 public key; private key material is never accepted or stored."""
        from datetime import datetime, timezone
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
        key_id = self._validate_evidence_key_id(key_id)
        actor = str(actor or "").strip()
        if not actor or len(actor) > 200:
            raise ValueError("actor must be 1..200 characters")
        raw = self._decode_ed25519_key(public_key_b64, "public_key")
        Ed25519PublicKey.from_public_bytes(raw)
        canonical_b64 = __import__("base64").b64encode(raw).decode("ascii")
        with connect(self.db_path) as db:
            existing = db.execute("SELECT * FROM risk_policy_evidence_signing_keys WHERE key_id=?", (key_id,)).fetchone()
            if existing:
                if existing["public_key_b64"] != canonical_b64:
                    raise ValueError("key_id already exists with a different public key")
                if existing["revoked_at"]:
                    raise ValueError("revoked key IDs cannot be reactivated or reused")
                return self._public_signing_key_row(existing)
            db.execute("INSERT INTO risk_policy_evidence_signing_keys(key_id,public_key_b64,created_by) VALUES(?,?,?)", (key_id, canonical_b64, actor))
            db.execute("INSERT INTO risk_policy_evidence_signing_key_audit(key_id,action,actor,details_json) VALUES(?,?,?,?)", (key_id, "registered", actor, json.dumps({"algorithm": "Ed25519"}, sort_keys=True)))
            row = db.execute("SELECT * FROM risk_policy_evidence_signing_keys WHERE key_id=?", (key_id,)).fetchone()
        return self._public_signing_key_row(row)

    def rotate_risk_policy_evidence_signing_key(self, old_key_id: str, new_key_id: str, new_public_key_b64: str, actor: str = "security-admin", reason: str = "planned rotation") -> dict:
        """Atomically register a replacement public key and revoke the previous key."""
        import base64
        from datetime import datetime, timezone
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
        old_id = self._validate_evidence_key_id(old_key_id)
        new_id = self._validate_evidence_key_id(new_key_id)
        actor_value = str(actor or "").strip()
        reason_value = str(reason or "").strip()
        if old_id == new_id:
            raise ValueError("new_key_id must differ from old_key_id")
        if not actor_value or len(actor_value) > 200:
            raise ValueError("actor must be 1..200 characters")
        if not reason_value or len(reason_value) > 1000:
            raise ValueError("reason must be 1..1000 characters")
        raw = self._decode_ed25519_key(new_public_key_b64, "new_public_key")
        Ed25519PublicKey.from_public_bytes(raw)
        canonical_b64 = base64.b64encode(raw).decode("ascii")
        now = datetime.now(timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z")
        with connect(self.db_path) as db:
            old = db.execute("SELECT * FROM risk_policy_evidence_signing_keys WHERE key_id=?", (old_id,)).fetchone()
            if old is None or old["revoked_at"]:
                raise ValueError("old signing key must exist and be active")
            existing = db.execute("SELECT * FROM risk_policy_evidence_signing_keys WHERE key_id=?", (new_id,)).fetchone()
            if existing:
                raise ValueError("new_key_id already exists and cannot be reused")
            db.execute("INSERT INTO risk_policy_evidence_signing_keys(key_id,public_key_b64,created_by) VALUES(?,?,?)", (new_id, canonical_b64, actor_value))
            db.execute("INSERT INTO risk_policy_evidence_signing_key_audit(key_id,action,actor,details_json) VALUES(?,?,?,?)", (new_id, "registered", actor_value, json.dumps({"algorithm": "Ed25519", "rotation_from": old_id}, sort_keys=True)))
            db.execute("UPDATE risk_policy_evidence_signing_keys SET revoked_by=?,revoked_at=?,revoked_reason=? WHERE key_id=?", (actor_value, now, reason_value, old_id))
            db.execute("INSERT INTO risk_policy_evidence_signing_key_audit(key_id,action,actor,details_json) VALUES(?,?,?,?)", (old_id, "revoked", actor_value, json.dumps({"reason": reason_value, "rotation_to": new_id}, sort_keys=True)))
            new = db.execute("SELECT * FROM risk_policy_evidence_signing_keys WHERE key_id=?", (new_id,)).fetchone()
        return {"rotated": True, "old_key_id": old_id, "old_key_revoked_at": now, "new_key": self._public_signing_key_row(new), "actor": actor_value}

    @staticmethod
    def _public_signing_key_row(row) -> dict:
        return {"key_id": row["key_id"], "algorithm": row["algorithm"], "public_key": row["public_key_b64"],
                "created_by": row["created_by"], "created_at": row["created_at"],
                "revoked": bool(row["revoked_at"]), "revoked_by": row["revoked_by"],
                "revoked_at": row["revoked_at"], "revoked_reason": row["revoked_reason"]}

    def list_risk_policy_evidence_signing_keys(self, include_revoked: bool = True) -> list[dict]:
        with connect(self.db_path) as db:
            if include_revoked:
                rows = db.execute("SELECT * FROM risk_policy_evidence_signing_keys ORDER BY key_id").fetchall()
            else:
                rows = db.execute("SELECT * FROM risk_policy_evidence_signing_keys WHERE revoked_at IS NULL ORDER BY key_id").fetchall()
        return [self._public_signing_key_row(row) for row in rows]

    def revoke_risk_policy_evidence_signing_key(self, key_id: str, actor: str = "security-admin", reason: str = "") -> dict:
        from datetime import datetime, timezone
        key_id = self._validate_evidence_key_id(key_id)
        actor = str(actor or "").strip()
        reason = str(reason or "").strip()
        if not actor or len(actor) > 200:
            raise ValueError("actor must be 1..200 characters")
        if not reason or len(reason) > 1000:
            raise ValueError("reason must be 1..1000 characters")
        now = datetime.now(timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z")
        with connect(self.db_path) as db:
            row = db.execute("SELECT * FROM risk_policy_evidence_signing_keys WHERE key_id=?", (key_id,)).fetchone()
            if row is None:
                raise ValueError(f"Signing key '{key_id}' does not exist")
            if not row["revoked_at"]:
                db.execute("UPDATE risk_policy_evidence_signing_keys SET revoked_by=?,revoked_at=?,revoked_reason=? WHERE key_id=?", (actor, now, reason, key_id))
                db.execute("INSERT INTO risk_policy_evidence_signing_key_audit(key_id,action,actor,details_json) VALUES(?,?,?,?)", (key_id, "revoked", actor, json.dumps({"reason": reason}, sort_keys=True)))
            row = db.execute("SELECT * FROM risk_policy_evidence_signing_keys WHERE key_id=?", (key_id,)).fetchone()
        return self._public_signing_key_row(row)

    def export_trust_registry_snapshot(self, signing_private_key: str, signer_key_id: str, actor: str = "security-auditor") -> dict:
        """Export a signed portable snapshot of public keys and their audit history."""
        from cybersec.trust_registry import create_snapshot
        keys = self.list_risk_policy_evidence_signing_keys(include_revoked=True)
        with connect(self.db_path) as db:
            rows = db.execute("SELECT id,key_id,action,actor,details_json,created_at FROM risk_policy_evidence_signing_key_audit ORDER BY id").fetchall()
        events = []
        for row in rows:
            item = dict(row)
            try: item["details"] = json.loads(item.pop("details_json") or "{}")
            except (TypeError, json.JSONDecodeError): item["details"] = {"unparsed_details": item.pop("details_json", "")}
            events.append(item)
        # Enforce that the supplied private key matches a registered, non-revoked signer.
        import base64
        from cryptography.hazmat.primitives import serialization
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
        raw = self._decode_ed25519_key(signing_private_key, "signing_private_key")
        private = Ed25519PrivateKey.from_private_bytes(raw)
        public_b64 = base64.b64encode(private.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)).decode("ascii")
        with connect(self.db_path) as db:
            row = db.execute("SELECT public_key_b64,revoked_at FROM risk_policy_evidence_signing_keys WHERE key_id=?", (signer_key_id,)).fetchone()
        if row is None or row["revoked_at"] or row["public_key_b64"] != public_b64:
            raise ValueError("signing key must match a registered, non-revoked trust-registry key")
        return create_snapshot(keys, events, signing_private_key, signer_key_id, actor)

    def list_risk_policy_evidence_signing_key_audit(self, key_id: str, limit: int = 100) -> list[dict]:
        key_id = self._validate_evidence_key_id(key_id)
        count = max(1, min(int(limit), 1000))
        with connect(self.db_path) as db:
            rows = db.execute("SELECT * FROM risk_policy_evidence_signing_key_audit WHERE key_id=? ORDER BY id DESC LIMIT ?", (key_id, count)).fetchall()
        result = []
        for row in rows:
            item = dict(row); item["details"] = json.loads(item.pop("details_json")); result.append(item)
        return result

    def export_risk_policy_evidence_bundle(self, evidence_id: int, signing_key: str | None = None, actor: str = "compliance-analyst", signing_private_key: str | None = None, key_id: str | None = None) -> dict:
        """Create a portable evidence bundle; supports legacy HMAC or Ed25519 signatures.

        Ed25519 private keys are raw 32-byte values encoded as base64 and are never persisted.
        The corresponding public key must be registered locally before verification succeeds.
        """
        import base64
        import hmac
        from datetime import datetime, timezone
        if signing_key is not None and signing_private_key is not None:
            raise ValueError("Use either legacy signing_key or signing_private_key, not both")
        key = self._policy_bundle_signing_key(signing_key)
        private_key = None
        normalized_key_id = None
        if signing_private_key is not None:
            from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
            private_key = Ed25519PrivateKey.from_private_bytes(self._decode_ed25519_key(signing_private_key, "signing_private_key"))
            if not key_id:
                raise ValueError("key_id is required for Ed25519 signing")
            normalized_key_id = self._validate_evidence_key_id(key_id)
            with connect(self.db_path) as db:
                registered = db.execute("SELECT public_key_b64,revoked_at FROM risk_policy_evidence_signing_keys WHERE key_id=?", (normalized_key_id,)).fetchone()
            if registered is None or registered["revoked_at"]:
                raise ValueError("Ed25519 signing key_id must be registered and not revoked")
            derived_public = private_key.public_key().public_bytes(__import__("cryptography.hazmat.primitives.serialization", fromlist=["Encoding"]).Encoding.Raw, __import__("cryptography.hazmat.primitives.serialization", fromlist=["PublicFormat"]).PublicFormat.Raw)
            if not hmac.compare_digest(derived_public, base64.b64decode(registered["public_key_b64"], validate=True)):
                raise ValueError("signing_private_key does not match the registered public key")
        evidence = self.get_risk_policy_evidence(evidence_id)
        if not evidence["integrity_valid"]:
            raise ValueError("Evidence integrity check failed; refusing to export bundle")
        snapshot = evidence["snapshot"]
        rule_versions = snapshot.get("rule_versions", [])
        core = {
            "format": "cybersec-policy-evidence-bundle", "schema_version": 1,
            "manifest": {"evidence_id": evidence["id"], "evaluation_id": evidence["evaluation_id"],
                "evidence_sha256": evidence["sha256"], "source_evidence_created_at": evidence["created_at"],
                "source_evidence_created_by": evidence["created_by"], "source_snapshot_sha256": evidence["sha256"],
                "rule_version_count": len(rule_versions),
                "created_at": datetime.now(timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z")},
            "evidence": {"created_by": evidence["created_by"], "created_at": evidence["created_at"], "snapshot": snapshot},
            "verification": {"evidence_integrity_valid": True, "verification_method": "sha256-canonical-json",
                "limitations": "Digest verification detects modification; a trusted Ed25519 public key is required to authenticate the signer."},
        }
        bundle_digest = hashlib.sha256(self._canonical_policy_bundle(core)).hexdigest()
        core["manifest"]["bundle_sha256"] = bundle_digest
        if private_key is not None:
            signature = base64.b64encode(private_key.sign(bundle_digest.encode("ascii"))).decode("ascii")
            core["signature"] = {"algorithm": "Ed25519", "key_id": normalized_key_id, "value": signature}
        elif key is None:
            core["signature"] = {"algorithm": "none", "value": None}
        else:
            signature = hmac.new(key, bundle_digest.encode("ascii"), hashlib.sha256).hexdigest()
            core["signature"] = {"algorithm": "HMAC-SHA256", "value": signature}
        self._record_policy_evidence_custody("bundle_exported", actor, evidence["id"], evidence["evaluation_id"], bundle_digest,
            {"signature_algorithm": core["signature"]["algorithm"], "key_id": core["signature"].get("key_id"), "schema_version": 1})
        return core

    def _verify_policy_evidence_bundle_payload(self, bundle, signing_key: str | None = None) -> dict:
        """Validate a bundle, resolving Ed25519 signers through the trusted-key registry."""
        import base64
        import hmac
        key = self._policy_bundle_signing_key(signing_key)
        if not isinstance(bundle, dict):
            raise ValueError("bundle must be a JSON object")
        if bundle.get("format") != "cybersec-policy-evidence-bundle" or bundle.get("schema_version") != 1:
            raise ValueError("Unsupported evidence bundle format or schema version")
        manifest, evidence, verification, signature = (bundle.get(k) for k in ("manifest", "evidence", "verification", "signature"))
        if not all(isinstance(item, dict) for item in (manifest, evidence, verification, signature)):
            raise ValueError("Bundle is missing manifest, evidence, verification, or signature objects")
        snapshot = evidence.get("snapshot")
        if not isinstance(snapshot, dict):
            raise ValueError("Bundle evidence snapshot must be an object")
        evidence_digest = hashlib.sha256(self._canonical_policy_bundle(snapshot)).hexdigest()
        evidence_integrity = hmac.compare_digest(evidence_digest, str(manifest.get("evidence_sha256", "")))
        core = {k: v for k, v in bundle.items() if k != "signature"}
        core_manifest = dict(core.get("manifest", {})); expected_bundle_digest = core_manifest.pop("bundle_sha256", None)
        core["manifest"] = core_manifest
        actual_bundle_digest = hashlib.sha256(self._canonical_policy_bundle(core)).hexdigest()
        bundle_integrity = isinstance(expected_bundle_digest, str) and hmac.compare_digest(actual_bundle_digest, expected_bundle_digest)
        algorithm = signature.get("algorithm"); signature_valid = None; key_id_value = signature.get("key_id")
        if algorithm == "HMAC-SHA256":
            if key is None:
                signature_valid = False
            else:
                expected_signature = hmac.new(key, str(expected_bundle_digest).encode("ascii"), hashlib.sha256).hexdigest()
                signature_valid = hmac.compare_digest(expected_signature, str(signature.get("value", "")))
        elif algorithm == "Ed25519":
            signature_valid = False
            try:
                key_id_value = self._validate_evidence_key_id(key_id_value)
                with connect(self.db_path) as db:
                    key_row = db.execute("SELECT public_key_b64,revoked_at FROM risk_policy_evidence_signing_keys WHERE key_id=?", (key_id_value,)).fetchone()
                if key_row is not None and not key_row["revoked_at"]:
                    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
                    public_key = Ed25519PublicKey.from_public_bytes(base64.b64decode(key_row["public_key_b64"], validate=True))
                    signature_bytes = base64.b64decode(str(signature.get("value", "")), validate=True)
                    public_key.verify(signature_bytes, str(expected_bundle_digest).encode("ascii"))
                    signature_valid = True
            except Exception:
                signature_valid = False
        elif algorithm == "none" and signature.get("value") is None:
            signature_valid = None
        else:
            raise ValueError("Unsupported bundle signature algorithm")
        valid = evidence_integrity and bundle_integrity and (signature_valid is not False)
        return {"valid": valid, "evidence_integrity_valid": evidence_integrity, "bundle_integrity_valid": bundle_integrity,
            "signature_algorithm": algorithm, "signature_valid": signature_valid, "key_id": key_id_value,
            "evidence_id": manifest.get("evidence_id"), "evaluation_id": manifest.get("evaluation_id"),
            "bundle_sha256": expected_bundle_digest,
            "limitations": "Unsigned bundles provide integrity checks only. HMAC requires a shared secret. Ed25519 verification requires a trusted, non-revoked public key registered in this repository."}

    def verify_risk_policy_evidence_bundle(self, bundle, signing_key: str | None = None, actor: str = "compliance-analyst") -> dict:
        """Verify bundle, persist a hash-chained custody event, and flag repeated valid digests."""
        result = self._verify_policy_evidence_bundle_payload(bundle, signing_key)
        digest = str(result.get("bundle_sha256") or "invalid-digest")
        with connect(self.db_path) as db:
            prior_rows = db.execute("SELECT details_json FROM risk_policy_evidence_custody WHERE bundle_sha256=? AND event_type='bundle_verified'", (digest,)).fetchall()
        replay = bool(result.get("valid") and any(json.loads(row["details_json"]).get("valid") for row in prior_rows))
        result["replay_detected"] = replay
        event_type = "bundle_verified" if result.get("valid") else "bundle_verification_failed"
        self._record_policy_evidence_custody(
            event_type, actor, result.get("evidence_id"), result.get("evaluation_id"), digest,
            {"valid": bool(result.get("valid")), "replay_detected": replay,
             "signature_algorithm": result.get("signature_algorithm"), "signature_valid": result.get("signature_valid")},
        )
        return result

    def _record_policy_evidence_custody(self, event_type: str, actor: str, evidence_id, evaluation_id, bundle_sha256: str, details: dict) -> dict:
        actor_value = str(actor or "").strip()
        if not actor_value or len(actor_value) > 200:
            raise ValueError("actor must be 1..200 characters")
        event_data = {"event_type": event_type, "actor": actor_value, "evidence_id": evidence_id,
                      "evaluation_id": evaluation_id, "bundle_sha256": bundle_sha256, "details": details}
        with connect(self.db_path) as db:
            db.execute("BEGIN IMMEDIATE")
            previous = db.execute("SELECT event_hash FROM risk_policy_evidence_custody ORDER BY id DESC LIMIT 1").fetchone()
            previous_hash = previous["event_hash"] if previous else None
            created_at = __import__("datetime").datetime.now(__import__("datetime").timezone.utc).isoformat(timespec="milliseconds").replace("+00:00", "Z")
            canonical = self._canonical_policy_bundle({**event_data, "previous_hash": previous_hash, "created_at": created_at})
            event_hash = hashlib.sha256(canonical).hexdigest()
            cur = db.execute("INSERT INTO risk_policy_evidence_custody(event_type,actor,evidence_id,evaluation_id,bundle_sha256,details_json,previous_hash,event_hash,created_at) VALUES(?,?,?,?,?,?,?,?,?)",
                             (event_type, actor_value, evidence_id, evaluation_id, bundle_sha256, json.dumps(details, sort_keys=True), previous_hash, event_hash, created_at))
            return {"id": cur.lastrowid, **event_data, "previous_hash": previous_hash, "event_hash": event_hash, "created_at": created_at}

    def list_risk_policy_evidence_custody(self, bundle_sha256: str | None = None, limit: int = 100) -> list[dict]:
        count = max(1, min(int(limit), 1000))
        with connect(self.db_path) as db:
            if bundle_sha256:
                rows = db.execute("SELECT * FROM risk_policy_evidence_custody WHERE bundle_sha256=? ORDER BY id DESC LIMIT ?", (bundle_sha256, count)).fetchall()
            else:
                rows = db.execute("SELECT * FROM risk_policy_evidence_custody ORDER BY id DESC LIMIT ?", (count,)).fetchall()
        result=[]
        for row in rows:
            item=dict(row); item["details"] = json.loads(item.pop("details_json")); result.append(item)
        return result

    def verify_risk_policy_evidence_custody_chain(self) -> dict:
        with connect(self.db_path) as db:
            rows = db.execute("SELECT * FROM risk_policy_evidence_custody ORDER BY id").fetchall()
        previous_hash = None
        checked = 0
        for row in rows:
            details = json.loads(row["details_json"])
            data = {"event_type": row["event_type"], "actor": row["actor"], "evidence_id": row["evidence_id"],
                    "evaluation_id": row["evaluation_id"], "bundle_sha256": row["bundle_sha256"], "details": details,
                    "previous_hash": previous_hash, "created_at": row["created_at"]}
            expected = hashlib.sha256(self._canonical_policy_bundle(data)).hexdigest()
            if row["previous_hash"] != previous_hash or not __import__("hmac").compare_digest(expected, row["event_hash"]):
                return {"valid": False, "checked_events": checked, "failed_event_id": row["id"]}
            previous_hash = row["event_hash"]; checked += 1
        return {"valid": True, "checked_events": checked, "head_hash": previous_hash}

    def create_risk_policy_evidence_custody_checkpoint(self, key_id: str, signing_private_key: str, actor: str = "security-auditor") -> dict:
        """Create an Ed25519-signed checkpoint suitable for storage outside this database."""
        import base64
        import uuid
        from datetime import datetime, timezone
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
        from cryptography.hazmat.primitives import serialization
        normalized_key_id = self._validate_evidence_key_id(key_id)
        actor_value = str(actor or "").strip()
        if not actor_value or len(actor_value) > 200:
            raise ValueError("actor must be 1..200 characters")
        private = Ed25519PrivateKey.from_private_bytes(self._decode_ed25519_key(signing_private_key, "signing_private_key"))
        with connect(self.db_path) as db:
            key_row = db.execute("SELECT public_key_b64,revoked_at FROM risk_policy_evidence_signing_keys WHERE key_id=?", (normalized_key_id,)).fetchone()
        if key_row is None or key_row["revoked_at"]:
            raise ValueError("Checkpoint key must be registered and not revoked")
        public_raw = private.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
        registered_raw = base64.b64decode(key_row["public_key_b64"], validate=True)
        if not __import__("hmac").compare_digest(public_raw, registered_raw):
            raise ValueError("signing_private_key does not match the registered public key")
        chain = self.verify_risk_policy_evidence_custody_chain()
        if not chain["valid"]:
            raise ValueError("Custody chain integrity check failed; refusing to checkpoint")
        payload = {
            "format": "cybersec-custody-checkpoint", "schema_version": 1,
            "checkpoint_id": str(uuid.uuid4()), "event_count": chain["checked_events"],
            "head_hash": chain["head_hash"], "key_id": normalized_key_id,
            "algorithm": "Ed25519", "created_by": actor_value,
            "created_at": datetime.now(timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z"),
        }
        message = self._canonical_policy_bundle(payload)
        signature = base64.b64encode(private.sign(message)).decode("ascii")
        checkpoint = {**payload, "public_key_b64": key_row["public_key_b64"], "signature_b64": signature}
        with connect(self.db_path) as db:
            db.execute("INSERT INTO risk_policy_evidence_custody_checkpoints(checkpoint_id,event_count,head_hash,key_id,public_key_b64,signature_b64,actor,created_at,payload_json) VALUES(?,?,?,?,?,?,?,?,?)",
                       (payload["checkpoint_id"], payload["event_count"], payload["head_hash"], normalized_key_id,
                        key_row["public_key_b64"], signature, actor_value, payload["created_at"], json.dumps(payload, sort_keys=True)))
        return checkpoint

    def list_risk_policy_evidence_custody_checkpoints(self, limit: int = 100) -> list[dict]:
        count = max(1, min(int(limit), 1000))
        with connect(self.db_path) as db:
            rows = db.execute("SELECT * FROM risk_policy_evidence_custody_checkpoints ORDER BY id DESC LIMIT ?", (count,)).fetchall()
        result = []
        for row in rows:
            item = dict(row)
            item["payload"] = json.loads(item.pop("payload_json"))
            item.pop("public_key_b64", None)
            item.pop("signature_b64", None)
            result.append(item)
        return result

    def verify_risk_policy_evidence_custody_checkpoint(self, checkpoint, trusted_public_key: str | None = None) -> dict:
        """Verify a checkpoint signature and compare its anchored chain prefix with local events.

        For independent verification, pass a public key obtained through an external trust channel.
        The public key embedded in a checkpoint is not trusted merely because it is embedded there.
        """
        import base64
        import hmac
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
        if not isinstance(checkpoint, dict) or checkpoint.get("format") != "cybersec-custody-checkpoint" or checkpoint.get("schema_version") != 1:
            raise ValueError("Unsupported custody checkpoint format or schema version")
        required = ("checkpoint_id", "event_count", "head_hash", "key_id", "algorithm", "created_by", "created_at", "signature_b64")
        if any(field not in checkpoint for field in required):
            raise ValueError("Checkpoint is missing required fields")
        if checkpoint.get("algorithm") != "Ed25519":
            raise ValueError("Unsupported checkpoint signature algorithm")
        key_id = self._validate_evidence_key_id(checkpoint.get("key_id"))
        key_b64 = trusted_public_key
        trust_source = "provided_external_key" if trusted_public_key else "local_trust_registry"
        if key_b64 is None:
            with connect(self.db_path) as db:
                row = db.execute("SELECT public_key_b64,revoked_at FROM risk_policy_evidence_signing_keys WHERE key_id=?", (key_id,)).fetchone()
            if row is None or row["revoked_at"]:
                return {"valid": False, "signature_valid": False, "chain_prefix_valid": False, "reason": "unknown_or_revoked_key", "key_id": key_id}
            key_b64 = row["public_key_b64"]
        try:
            public_raw = self._decode_ed25519_key(key_b64, "trusted_public_key")
            public = Ed25519PublicKey.from_public_bytes(public_raw)
            payload = {field: checkpoint[field] for field in ("format", "schema_version", "checkpoint_id", "event_count", "head_hash", "key_id", "algorithm", "created_by", "created_at")}
            signature = base64.b64decode(checkpoint["signature_b64"], validate=True)
            public.verify(signature, self._canonical_policy_bundle(payload))
            signature_valid = True
        except Exception:
            signature_valid = False
        if not signature_valid:
            return {"valid": False, "signature_valid": False, "chain_prefix_valid": False, "reason": "invalid_signature", "key_id": key_id, "trust_source": trust_source}
        try:
            event_count = int(checkpoint["event_count"])
        except (TypeError, ValueError):
            raise ValueError("event_count must be an integer")
        if event_count < 0:
            raise ValueError("event_count must be zero or greater")
        with connect(self.db_path) as db:
            rows = db.execute("SELECT * FROM risk_policy_evidence_custody ORDER BY id LIMIT ?", (event_count,)).fetchall()
        prefix_ok = len(rows) == event_count
        previous_hash = None
        checked = 0
        for row in rows:
            details = json.loads(row["details_json"])
            data = {"event_type": row["event_type"], "actor": row["actor"], "evidence_id": row["evidence_id"],
                    "evaluation_id": row["evaluation_id"], "bundle_sha256": row["bundle_sha256"], "details": details,
                    "previous_hash": previous_hash, "created_at": row["created_at"]}
            expected = hashlib.sha256(self._canonical_policy_bundle(data)).hexdigest()
            if row["previous_hash"] != previous_hash or not hmac.compare_digest(expected, row["event_hash"]):
                prefix_ok = False
                break
            previous_hash = row["event_hash"]
            checked += 1
        expected_head = previous_hash if event_count else None
        if checkpoint.get("head_hash") != expected_head:
            prefix_ok = False
        return {"valid": bool(signature_valid and prefix_ok), "signature_valid": signature_valid,
                "chain_prefix_valid": prefix_ok, "checked_events": checked, "event_count": event_count,
                "head_hash": expected_head, "key_id": key_id, "trust_source": trust_source,
                "reason": None if prefix_ok else "checkpoint_chain_prefix_mismatch"}

    @staticmethod
    def _policy_exception_expiry(value: str) -> str:
        from datetime import datetime, timezone
        if not isinstance(value, str) or not value.strip():
            raise ValueError("expires_at must be an ISO-8601 timestamp")
        try:
            parsed = datetime.fromisoformat(value.strip().replace("Z", "+00:00"))
        except ValueError as exc:
            raise ValueError("expires_at must be an ISO-8601 timestamp") from exc
        if parsed.tzinfo is None:
            raise ValueError("expires_at must include a timezone")
        parsed = parsed.astimezone(timezone.utc)
        if parsed <= datetime.now(timezone.utc):
            raise ValueError("expires_at must be in the future")
        return parsed.isoformat(timespec="seconds").replace("+00:00", "Z")

    @staticmethod
    def _expire_policy_exceptions(db) -> int:
        from datetime import datetime, timezone
        now = datetime.now(timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z")
        rows = db.execute("SELECT id FROM risk_policy_exceptions WHERE status IN ('approved','pending') AND expires_at<=?", (now,)).fetchall()
        for row in rows:
            db.execute("UPDATE risk_policy_exceptions SET status='expired' WHERE id=?", (row["id"],))
            db.execute("INSERT INTO risk_policy_exception_audit(exception_id,action,actor,details_json) VALUES(?,?,?,?)",
                       (row["id"], "expired", "policy-engine", json.dumps({"reason": "exception expiry reached"})))
        return len(rows)

    def create_risk_policy_exception(self, rule_id: int, requested_by: str, reviewer: str, reason: str, expires_at: str) -> dict:
        self.get_risk_intelligence_rule(rule_id)
        requested_by = self._risk_rule_actor(requested_by)
        reviewer = self._risk_rule_actor(reviewer)
        reason = str(reason).strip() if isinstance(reason, str) else ""
        if not reason or len(reason) > 1000:
            raise ValueError("reason is required and must be at most 1000 characters")
        if requested_by.casefold() == reviewer.casefold():
            raise ValueError("reviewer must be different from requester")
        expiry = self._policy_exception_expiry(expires_at)
        with connect(self.db_path) as db:
            cursor = db.execute("INSERT INTO risk_policy_exceptions(rule_id,requested_by,reviewer,reason,expires_at) VALUES(?,?,?,?,?)", (rule_id, requested_by, reviewer, reason, expiry))
            exception_id = int(cursor.lastrowid)
            db.execute("INSERT INTO risk_policy_exception_audit(exception_id,action,actor,details_json) VALUES(?,?,?,?)", (exception_id, "requested", requested_by, json.dumps({"reviewer": reviewer, "expires_at": expiry, "reason": reason}, sort_keys=True)))
        return self.get_risk_policy_exception(exception_id)

    def get_risk_policy_exception(self, exception_id: int) -> dict:
        if isinstance(exception_id, bool) or not isinstance(exception_id, int) or exception_id < 1:
            raise ValueError("exception_id must be a positive integer")
        with connect(self.db_path) as db:
            self._expire_policy_exceptions(db)
            row = db.execute("SELECT * FROM risk_policy_exceptions WHERE id=?", (exception_id,)).fetchone()
        if row is None:
            raise ValueError(f"Policy exception #{exception_id} does not exist.")
        return dict(row)

    def list_risk_policy_exceptions(self, rule_id: int | None = None, limit: int = 100) -> dict:
        if isinstance(limit, bool) or not isinstance(limit, int) or not 1 <= limit <= 500:
            raise ValueError("limit must be between 1 and 500")
        if rule_id is not None:
            self.get_risk_intelligence_rule(rule_id)
        with connect(self.db_path) as db:
            self._expire_policy_exceptions(db)
            if rule_id is None:
                rows = db.execute("SELECT * FROM risk_policy_exceptions ORDER BY id DESC LIMIT ?", (limit,)).fetchall()
            else:
                rows = db.execute("SELECT * FROM risk_policy_exceptions WHERE rule_id=? ORDER BY id DESC LIMIT ?", (rule_id, limit)).fetchall()
        items = [dict(row) for row in rows]
        return {"items": items, "total": len(items), "limit": limit}

    def review_risk_policy_exception(self, exception_id: int, reviewer: str, decision: str, note: str = "") -> dict:
        reviewer = self._risk_rule_actor(reviewer)
        decision = str(decision).strip().lower()
        if decision not in ("approved", "rejected"):
            raise ValueError("decision must be approved or rejected")
        note = str(note).strip() if isinstance(note, str) else ""
        if len(note) > 1000:
            raise ValueError("review note must be at most 1000 characters")
        exception = self.get_risk_policy_exception(exception_id)
        if exception["status"] != "pending":
            raise ValueError("only pending exceptions can be reviewed")
        if reviewer.casefold() != exception["reviewer"].casefold():
            raise ValueError("only the assigned reviewer can review this exception")
        with connect(self.db_path) as db:
            db.execute("UPDATE risk_policy_exceptions SET status=?,reviewed_by=?,reviewed_at=strftime('%Y-%m-%dT%H:%M:%fZ','now'),review_note=? WHERE id=? AND status='pending'", (decision, reviewer, note, exception_id))
            if db.total_changes == 0:
                raise ValueError("exception was already reviewed")
            db.execute("INSERT INTO risk_policy_exception_audit(exception_id,action,actor,details_json) VALUES(?,?,?,?)", (exception_id, decision, reviewer, json.dumps({"note": note}, sort_keys=True)))
        return self.get_risk_policy_exception(exception_id)

    def revoke_risk_policy_exception(self, exception_id: int, actor: str, reason: str) -> dict:
        actor = self._risk_rule_actor(actor)
        reason = str(reason).strip() if isinstance(reason, str) else ""
        if not reason or len(reason) > 1000:
            raise ValueError("reason is required and must be at most 1000 characters")
        exception = self.get_risk_policy_exception(exception_id)
        if exception["status"] not in ("pending", "approved"):
            raise ValueError("only pending or approved exceptions can be revoked")
        with connect(self.db_path) as db:
            db.execute("UPDATE risk_policy_exceptions SET status='revoked',reviewed_by=?,reviewed_at=strftime('%Y-%m-%dT%H:%M:%fZ','now'),review_note=? WHERE id=?", (actor, reason, exception_id))
            db.execute("INSERT INTO risk_policy_exception_audit(exception_id,action,actor,details_json) VALUES(?,?,?,?)", (exception_id, "revoked", actor, json.dumps({"reason": reason}, sort_keys=True)))
        return self.get_risk_policy_exception(exception_id)

    def list_risk_policy_exception_audit(self, exception_id: int, limit: int = 100) -> dict:
        self.get_risk_policy_exception(exception_id)
        if isinstance(limit, bool) or not isinstance(limit, int) or not 1 <= limit <= 500:
            raise ValueError("limit must be between 1 and 500")
        with connect(self.db_path) as db:
            rows = db.execute("SELECT * FROM risk_policy_exception_audit WHERE exception_id=? ORDER BY id DESC LIMIT ?", (exception_id, limit)).fetchall()
        items = []
        for row in rows:
            item = dict(row); item["details"] = json.loads(item.pop("details_json")); items.append(item)
        return {"items": items, "total": len(items), "limit": limit}

    def get_risk_policy_retention(self) -> dict:
        with connect(self.db_path) as db:
            row = db.execute("SELECT * FROM risk_policy_retention_settings WHERE id=1").fetchone()
        return dict(row)

    def set_risk_policy_retention(self, retention_days: int, actor: str = "admin") -> dict:
        actor = self._risk_rule_actor(actor)
        if isinstance(retention_days, bool) or not isinstance(retention_days, int) or not 1 <= retention_days <= 3650:
            raise ValueError("retention_days must be between 1 and 3650")
        with connect(self.db_path) as db:
            db.execute("UPDATE risk_policy_retention_settings SET retention_days=?,updated_by=?,updated_at=strftime('%Y-%m-%dT%H:%M:%fZ','now') WHERE id=1", (retention_days, actor))
        return self.get_risk_policy_retention()

    def prune_risk_policy_evaluations(self, actor: str = "retention-worker", *, dry_run: bool = True) -> dict:
        actor = self._risk_rule_actor(actor)
        if not isinstance(dry_run, bool):
            raise ValueError("dry_run must be a boolean")
        from datetime import datetime, timedelta, timezone
        settings = self.get_risk_policy_retention()
        cutoff = (datetime.now(timezone.utc) - timedelta(days=settings["retention_days"])).isoformat(timespec="seconds").replace("+00:00", "Z")
        with connect(self.db_path) as db:
            rows = db.execute("SELECT id,created_at FROM risk_intelligence_policy_evaluations WHERE created_at < ? ORDER BY id", (cutoff,)).fetchall()
            ids = [row["id"] for row in rows]
            if ids and not dry_run:
                db.executemany("DELETE FROM risk_intelligence_policy_evaluations WHERE id=?", [(value,) for value in ids])
        return {"actor": actor, "retention_days": settings["retention_days"], "cutoff": cutoff, "matched": len(ids), "deleted": 0 if dry_run else len(ids), "dry_run": dry_run, "evaluation_ids": ids}

    def compare_risk_intelligence_rule_versions(self, rule_id: int, before_version: int, after_version: int) -> dict:
        self.get_risk_intelligence_rule(rule_id)
        if any(isinstance(v,bool) or not isinstance(v,int) or v<1 for v in (before_version,after_version)): raise ValueError("version numbers must be positive integers")
        with connect(self.db_path) as db:
            rows=db.execute("SELECT version_number,snapshot_json FROM risk_intelligence_rule_versions WHERE rule_id=? AND version_number IN (?,?)",(rule_id,before_version,after_version)).fetchall()
        snapshots={r["version_number"]:json.loads(r["snapshot_json"]) for r in rows}
        if before_version not in snapshots or after_version not in snapshots: raise ValueError("One or both versions do not exist")
        outcomes={}
        for version,snapshot in ((before_version,snapshots[before_version]),(after_version,snapshots[after_version])):
            preview=self.refresh_risk_intelligence(snapshot["config"],persist=False)
            items=preview["items"]
            outcomes[str(version)]={"version_number":version,"name":snapshot["name"],"enabled":snapshot["enabled"],"total_signals":len(items),"by_severity":{sev:sum(1 for x in items if x["severity"]==sev) for sev in ("critical","high","warning","info")}}
        return {"rule_id":rule_id,"before":outcomes[str(before_version)],"after":outcomes[str(after_version)],"signal_delta":outcomes[str(after_version)]["total_signals"]-outcomes[str(before_version)]["total_signals"],"note":"Both versions were previewed against the same local stored metadata; no alerts, scanners, or outbound requests were triggered."}

    def export_risk_intelligence_rules(self, rule_ids: list[int] | None = None) -> dict:
        if rule_ids is not None and (not isinstance(rule_ids,list) or any(isinstance(x,bool) or not isinstance(x,int) or x<1 for x in rule_ids) or len(set(rule_ids))!=len(rule_ids)): raise ValueError("rule_ids must be a list of unique positive integers")
        all_rules=self.list_risk_intelligence_rules()
        selected=[r for r in all_rules["items"] if rule_ids is None or r["id"] in rule_ids]
        if rule_ids is not None and len(selected)!=len(rule_ids): raise ValueError("One or more requested rules do not exist")
        payload={"format":"cybersec-risk-rules","schema_version":1,"rules":[{"name":r["name"],"description":r["description"],"config":r["config"],"enabled":r["enabled"]} for r in selected]}
        canonical=json.dumps(payload,sort_keys=True,separators=(",",":"),ensure_ascii=False)
        return {**payload,"sha256":hashlib.sha256(canonical.encode("utf-8")).hexdigest()}

    def import_risk_intelligence_rules(self, bundle: dict, actor: str = "import") -> dict:
        actor=self._risk_rule_actor(actor)
        if not isinstance(bundle,dict): raise ValueError("Import bundle must be a JSON object")
        payload={k:bundle[k] for k in ("format","schema_version","rules") if k in bundle}
        if payload.get("format")!="cybersec-risk-rules" or payload.get("schema_version")!=1 or not isinstance(payload.get("rules"),list): raise ValueError("Unsupported risk-rule bundle format or schema version")
        canonical=json.dumps(payload,sort_keys=True,separators=(",",":"),ensure_ascii=False)
        digest=hashlib.sha256(canonical.encode("utf-8")).hexdigest()
        if not isinstance(bundle.get("sha256"),str) or not __import__("hmac").compare_digest(digest,bundle["sha256"]): raise ValueError("Risk-rule bundle integrity check failed")
        if len(payload["rules"])>500: raise ValueError("Import bundle may contain at most 500 rules")
        validated=[]
        for entry in payload["rules"]:
            if not isinstance(entry,dict) or set(entry)-{"name","description","config","enabled"}: raise ValueError("Invalid rule entry in import bundle")
            name=str(entry.get("name","")).strip(); description=str(entry.get("description","")).strip(); enabled=entry.get("enabled",True)
            if not name or len(name)>120 or len(description)>1000 or not isinstance(enabled,bool): raise ValueError("Invalid rule name, description, or enabled flag")
            config=self._validate_risk_rule_config(entry.get("config",{}))
            validated.append({"name":name,"description":description,"enabled":enabled,"config":config})
        imported=[]
        for entry in validated:
            try: imported.append(self.save_risk_intelligence_rule({**entry,"actor":actor}))
            except ValueError as exc:
                if "already exists" not in str(exc): raise
                existing=next(r for r in self.list_risk_intelligence_rules()["items"] if r["name"].casefold()==entry["name"].casefold())
                imported.append(self.save_risk_intelligence_rule({**entry,"id":existing["id"],"actor":actor}))
        return {"imported":len(imported),"items":imported,"integrity":"verified"}

    def compare_risk_intelligence_rules(self, rule_ids: list[int], actor: str = "analyst") -> dict:
        if not isinstance(rule_ids, list) or not 2 <= len(rule_ids) <= 10:
            raise ValueError("Provide between 2 and 10 rule IDs to compare")
        if any(isinstance(item, bool) or not isinstance(item, int) or item < 1 for item in rule_ids):
            raise ValueError("Rule IDs must be positive integers")
        if len(set(rule_ids)) != len(rule_ids):
            raise ValueError("Rule IDs must be unique")
        results = []
        for rule_id in rule_ids:
            rule = self.get_risk_intelligence_rule(rule_id)
            preview = self.refresh_risk_intelligence(rule["config"], persist=False)
            items = preview["items"]
            counts = {key: 0 for key in ("P1", "P2", "P3", "P4")}
            for item in items:
                counts[item.get("details", {}).get("priority", "P4")] += 1
            results.append({"id": rule["id"], "name": rule["name"], "enabled": rule["enabled"], "config": rule["config"], "total_signals": len(items), "by_priority": counts, "by_severity": {severity: sum(1 for item in items if item["severity"] == severity) for severity in ("critical", "high", "warning", "info")}, "signals": items})
        actor = self._risk_rule_actor(actor)
        summary = [{"id": item["id"], "name": item["name"], "enabled": item["enabled"], "total_signals": item["total_signals"], "by_priority": item["by_priority"], "by_severity": item["by_severity"]} for item in results]
        note = "All rule sets were evaluated against the same stored local metadata; comparison history is saved but does not save alerts; scanners and outbound requests are not executed."
        full_result = {"compared": len(results), "results": results, "summary": summary, "created_by": actor, "note": note}
        with connect(self.db_path) as db:
            cursor = db.execute("INSERT INTO risk_intelligence_comparison_history(rule_ids_json,summary_json,result_json,created_by) VALUES(?,?,?,?)", (json.dumps(rule_ids), json.dumps(summary, sort_keys=True), json.dumps(full_result, sort_keys=True), actor))
            comparison_id = int(cursor.lastrowid)
        return {"id": comparison_id, **full_result}

    @staticmethod
    def _risk_alert_priority(severity: str, criticality: str = "medium", boost: bool = True) -> str:
        order = {"critical": 0, "high": 1, "warning": 2, "info": 3}
        index = order.get(severity, 3)
        if boost and criticality == "critical":
            index = max(0, index - 2)
        elif boost and criticality == "high":
            index = max(0, index - 1)
        return ("P1", "P2", "P3", "P4")[index]

    def refresh_risk_intelligence(self, config: dict | None = None, *, persist: bool = True) -> dict:
        """Analyze stored data using configurable thresholds; preview mode never writes alert rows."""
        from datetime import date, timedelta
        settings = {key: value for key, value in self.get_risk_intelligence_config().items() if key in self._RISK_INTELLIGENCE_DEFAULTS}
        if config is not None:
            # Validate a candidate through the same schema without mutating saved policy.
            candidate = {**settings, **config}
            window = candidate.get("window_days")
            minimum = candidate.get("minimum_findings")
            ratio = candidate.get("growth_ratio")
            boost = candidate.get("criticality_boost")
            if isinstance(window, bool) or not isinstance(window, int) or not 1 <= window <= 90:
                raise ValueError("window_days must be an integer between 1 and 90")
            if isinstance(minimum, bool) or not isinstance(minimum, int) or not 1 <= minimum <= 10000:
                raise ValueError("minimum_findings must be an integer between 1 and 10000")
            if isinstance(ratio, bool) or not isinstance(ratio, (int, float)) or not 1 <= float(ratio) <= 100:
                raise ValueError("growth_ratio must be between 1 and 100")
            if not isinstance(boost, bool):
                raise ValueError("criticality_boost must be a boolean")
            if set(config) - set(self._RISK_INTELLIGENCE_DEFAULTS):
                raise ValueError("Unknown configuration fields: " + ", ".join(sorted(set(config) - set(self._RISK_INTELLIGENCE_DEFAULTS))))
            settings = candidate
        window_days = settings["window_days"]
        minimum_findings = settings["minimum_findings"]
        growth_ratio = float(settings["growth_ratio"])
        criticality_boost = settings["criticality_boost"]
        today = date.today()
        current_start = (today - timedelta(days=window_days - 1)).isoformat()
        previous_start = (today - timedelta(days=2 * window_days - 1)).isoformat()
        previous_end = (today - timedelta(days=window_days)).isoformat()
        current_end = today.isoformat()
        detected: dict[str, dict] = {}
        with connect(self.db_path) as db:
            growth_rows = db.execute("""
                SELECT t.id target_id,t.url target_url,t.criticality,
                    SUM(CASE WHEN substr(f.created_at,1,10) BETWEEN ? AND ? THEN 1 ELSE 0 END) current_count,
                    SUM(CASE WHEN substr(f.created_at,1,10) BETWEEN ? AND ? THEN 1 ELSE 0 END) previous_count
                FROM targets t JOIN normalized_findings f ON f.target_id=t.id
                GROUP BY t.id HAVING current_count >= ? AND (previous_count = 0 OR current_count >= previous_count * ?)
            """, (current_start, current_end, previous_start, previous_end, minimum_findings, growth_ratio)).fetchall()
            for row in growth_rows:
                key = f"target_finding_growth:{row['target_id']}"
                detected[key] = {"alert_key": key, "alert_type": "target_finding_growth",
                    "severity": "high" if row['criticality'] in {'high','critical'} else "warning",
                    "title": "Finding volume increased for target",
                    "explanation": f"{row['current_count']} findings were recorded in the last {window_days} days versus {row['previous_count']} in the preceding {window_days} days. This may indicate newly discovered exposure or a change in assessment coverage.",
                    "details": {"target_id": row['target_id'], "target_url": row['target_url'], "target_criticality": row['criticality'], "current_window": row['current_count'], "previous_window": row['previous_count'], "window_days": window_days}}

            recurring_rows = db.execute("""
                SELECT f.id finding_id,f.target_id,t.url target_url,t.criticality target_criticality,f.title,f.fingerprint,f.severity,
                       o.observed_at,rt.id task_id
                FROM normalized_findings f
                JOIN targets t ON t.id=f.target_id
                JOIN finding_observations o ON o.finding_id=f.id
                JOIN remediation_tasks rt ON rt.finding_id=f.id AND rt.status='resolved'
                WHERE o.observed_at > COALESCE((SELECT MAX(h.changed_at) FROM remediation_history h
                    WHERE h.task_id=rt.id AND h.new_status='resolved'), '9999')
                GROUP BY f.id
            """).fetchall()
            for row in recurring_rows:
                key = f"recurring_finding:{row['finding_id']}"
                detected[key] = {"alert_key": key, "alert_type": "recurring_finding",
                    "severity": "critical" if row['severity'] == 'Critical' else "high",
                    "title": "Finding reappeared after remediation",
                    "explanation": "A matching finding fingerprint was recorded after the earlier finding had a remediation task marked resolved. Verify recurrence and check whether the prior fix was incomplete or the issue was reintroduced.",
                    "details": {"finding_id": row['finding_id'], "task_id": row['task_id'], "target_id": row['target_id'], "target_url": row['target_url'], "target_criticality": row['target_criticality'], "finding_title": row['title'], "fingerprint": row['fingerprint'], "observed_again_at": row['observed_at']}}

            overdue_rows = db.execute("""
                SELECT COUNT(*) total, SUM(CASE WHEN f.severity='Critical' THEN 1 ELSE 0 END) critical_count
                FROM remediation_tasks rt JOIN normalized_findings f ON f.id=rt.finding_id
                WHERE rt.due_date IS NOT NULL AND rt.due_date < ? AND rt.status NOT IN ('resolved','accepted')
            """, (today.isoformat(),)).fetchone()
            overdue = int(overdue_rows['total'] or 0)
            if overdue:
                key = "sla_backlog:global"
                detected[key] = {"alert_key": key, "alert_type": "sla_backlog",
                    "severity": "critical" if int(overdue_rows['critical_count'] or 0) else "high",
                    "title": "Overdue remediation backlog detected",
                    "explanation": f"{overdue} active remediation tasks are past their due date; {int(overdue_rows['critical_count'] or 0)} are associated with Critical findings. Review owners, blockers, and revised deadlines.",
                    "details": {"overdue_tasks": overdue, "critical_findings": int(overdue_rows['critical_count'] or 0)}}

            for item in detected.values():
                target_criticality = item.get("details", {}).get("target_criticality", "medium")
                item["details"]["priority"] = self._risk_alert_priority(item["severity"], target_criticality, criticality_boost)
                item["details"]["criticality_boost_enabled"] = criticality_boost
                item["details"]["rule_config"] = {"window_days": window_days, "minimum_findings": minimum_findings, "growth_ratio": growth_ratio}
            if not persist:
                return {"items": [{"id": None, **item, "status": "preview", "first_seen": None, "last_seen": None, "acknowledged_by": "", "acknowledged_at": None} for item in detected.values()], "total": len(detected), "preview": True, "config": settings, "note": "Preview uses saved local data and does not persist alerts or trigger scans."}
            existing = {r['alert_key']: r for r in db.execute("SELECT * FROM risk_intelligence_alerts").fetchall()}
            for key, item in detected.items():
                prior = existing.get(key)
                details = json.dumps(item['details'], sort_keys=True)
                if prior:
                    status = prior['status'] if prior['status'] == 'acknowledged' else 'open'
                    db.execute("UPDATE risk_intelligence_alerts SET alert_type=?,severity=?,title=?,explanation=?,details_json=?,status=?,last_seen=strftime('%Y-%m-%dT%H:%M:%fZ','now') WHERE alert_key=?",
                        (item['alert_type'], item['severity'], item['title'], item['explanation'], details, status, key))
                else:
                    db.execute("INSERT INTO risk_intelligence_alerts(alert_key,alert_type,severity,title,explanation,details_json) VALUES(?,?,?,?,?,?)",
                        (key, item['alert_type'], item['severity'], item['title'], item['explanation'], details))
            for key, prior in existing.items():
                if key not in detected and prior['status'] != 'resolved':
                    db.execute("UPDATE risk_intelligence_alerts SET status='resolved',last_seen=strftime('%Y-%m-%dT%H:%M:%fZ','now') WHERE alert_key=?", (key,))
        return self.list_risk_intelligence_alerts()

    def list_risk_intelligence_alerts(self, status: str | None = None, limit: int = 100, *, alert_type: str | None = None, severity: str | None = None, priority: str | None = None) -> dict:
        if isinstance(limit, bool) or not isinstance(limit, int) or not 1 <= limit <= 500:
            raise ValueError("limit must be between 1 and 500")
        if status is not None and status not in {"open", "acknowledged", "resolved"}:
            raise ValueError("status must be open, acknowledged, or resolved")
        if alert_type is not None and alert_type not in {"target_finding_growth", "recurring_finding", "sla_backlog"}:
            raise ValueError("alert_type must be target_finding_growth, recurring_finding, or sla_backlog")
        if severity is not None and severity not in {"info", "warning", "high", "critical"}:
            raise ValueError("severity must be info, warning, high, or critical")
        if priority is not None and priority not in {"P1", "P2", "P3", "P4"}:
            raise ValueError("priority must be P1, P2, P3, or P4")
        clauses, args = [], []
        for column, value in (("status", status), ("alert_type", alert_type), ("severity", severity)):
            if value is not None:
                clauses.append(f"{column}=?")
                args.append(value)
        where = (" WHERE " + " AND ".join(clauses)) if clauses else ""
        with connect(self.db_path) as db:
            rows = db.execute("SELECT * FROM risk_intelligence_alerts" + where + " ORDER BY CASE severity WHEN 'critical' THEN 0 WHEN 'high' THEN 1 WHEN 'warning' THEN 2 ELSE 3 END, last_seen DESC", args).fetchall()
        items = []
        for row in rows:
            item = dict(row)
            item['details'] = json.loads(item.pop('details_json'))
            if priority is None or item['details'].get('priority', 'P4') == priority:
                items.append(item)
        total = len(items)
        return {"items": items[:limit], "total": total, "limit": limit, "status_filter": status, "type_filter": alert_type, "severity_filter": severity, "priority_filter": priority}

    def acknowledge_risk_intelligence_alert(self, alert_id: int, acknowledged_by: str) -> dict:
        who = str(acknowledged_by).strip()
        if not who or len(who) > 120:
            raise ValueError("acknowledged_by must contain 1 to 120 characters")
        with connect(self.db_path) as db:
            row = db.execute("SELECT * FROM risk_intelligence_alerts WHERE id=?", (alert_id,)).fetchone()
            if row is None:
                raise ValueError(f"Risk alert #{alert_id} does not exist.")
            if row['status'] == 'resolved':
                raise ValueError("Resolved alerts cannot be acknowledged")
            db.execute("UPDATE risk_intelligence_alerts SET status='acknowledged',acknowledged_by=?,acknowledged_at=strftime('%Y-%m-%dT%H:%M:%fZ','now') WHERE id=?", (who, alert_id))
            updated = db.execute("SELECT * FROM risk_intelligence_alerts WHERE id=?", (alert_id,)).fetchone()
        item = dict(updated)
        item['details'] = json.loads(item.pop('details_json'))
        return item

    def export_data(self) -> dict:
        with connect(self.db_path) as db:
            targets = [dict(r) for r in db.execute("SELECT * FROM targets ORDER BY id")]
            jobs = [dict(r) for r in db.execute("SELECT * FROM scan_jobs ORDER BY id")]
            findings = [dict(r) for r in db.execute("SELECT * FROM normalized_findings ORDER BY id")]
            artifacts = [dict(r) for r in db.execute("SELECT * FROM scan_artifacts ORDER BY id")]
        artifacts_by_job: dict[int, list[int]] = {}
        for artifact in artifacts:
            artifacts_by_job.setdefault(int(artifact["job_id"]), []).append(int(artifact["id"]))
        for item in findings:
            item["risk_assessment"] = assess_risk(item["severity"], item["confidence"], item["vuln_type"]).to_dict()
            item["source_artifact_ids"] = artifacts_by_job.get(int(item["job_id"]), []) if item.get("job_id") is not None else []
        return {"schema_version": 4, "targets": targets, "jobs": jobs, "findings": findings, "scan_artifacts": artifacts}

    @staticmethod
    def _job(row: sqlite3.Row) -> ScanJob:
        return ScanJob(row["id"], row["target_id"], row["tool"], row["status"], row["created_at"],
                       row["started_at"], row["finished_at"], row["error"])

    @staticmethod
    def _finding(row: sqlite3.Row) -> Finding:
        return Finding(row["id"], row["target_id"], row["job_id"], row["title"], row["severity"],
                       row["confidence"], row["url"], row["vuln_type"], row["parameter"],
                       row["evidence"], row["recommendation"], row["source_tool"], row["created_at"])
