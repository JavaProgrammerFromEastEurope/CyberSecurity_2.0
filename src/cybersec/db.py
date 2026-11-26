"""SQLite persistence layer."""
from __future__ import annotations

import sqlite3
import json
from contextlib import contextmanager
from pathlib import Path
from typing import Iterator


SCHEMA = """
CREATE TABLE IF NOT EXISTS sqlmap_confirmations (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    finding_id INTEGER NOT NULL REFERENCES normalized_findings(id) ON DELETE CASCADE,
    target_id INTEGER NOT NULL REFERENCES targets(id) ON DELETE CASCADE,
    candidate_url TEXT NOT NULL,
    parameter TEXT NOT NULL,
    requested_by TEXT NOT NULL,
    approved_by TEXT,
    status TEXT NOT NULL DEFAULT 'pending' CHECK (status IN ('pending','approved','claimed','completed','failed')),
    summary TEXT,
    created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now')),
    approved_at TEXT,
    claimed_at TEXT,
    finished_at TEXT
);
CREATE INDEX IF NOT EXISTS idx_sqlmap_confirmations_status ON sqlmap_confirmations(status, id);

PRAGMA foreign_keys = ON;

CREATE TABLE IF NOT EXISTS targets (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    url TEXT NOT NULL UNIQUE,
    hostname TEXT NOT NULL,
    authorized INTEGER NOT NULL DEFAULT 0 CHECK (authorized IN (0, 1)),
    criticality TEXT NOT NULL DEFAULT 'medium' CHECK (criticality IN ('low', 'medium', 'high', 'critical')),
    created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now'))
);

CREATE TABLE IF NOT EXISTS scan_jobs (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    target_id INTEGER NOT NULL REFERENCES targets(id) ON DELETE CASCADE,
    tool TEXT NOT NULL,
    status TEXT NOT NULL DEFAULT 'queued'
        CHECK (status IN ('queued', 'running', 'completed', 'failed', 'cancelled')),
    created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now')),
    started_at TEXT,
    finished_at TEXT,
    error TEXT
);

CREATE TABLE IF NOT EXISTS scan_recovery_audit (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    old_job_id INTEGER NOT NULL REFERENCES scan_jobs(id),
    new_job_id INTEGER NOT NULL UNIQUE REFERENCES scan_jobs(id),
    acknowledged_by TEXT NOT NULL,
    created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now'))
);

CREATE TABLE IF NOT EXISTS normalized_findings (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    target_id INTEGER NOT NULL REFERENCES targets(id) ON DELETE CASCADE,
    job_id INTEGER REFERENCES scan_jobs(id) ON DELETE SET NULL,
    title TEXT NOT NULL,
    severity TEXT NOT NULL CHECK (severity IN ('Critical', 'High', 'Medium', 'Low', 'Info')),
    confidence TEXT NOT NULL CHECK (confidence IN ('Certain', 'Firm', 'Tentative', 'Unknown')),
    url TEXT NOT NULL,
    vuln_type TEXT NOT NULL,
    parameter TEXT,
    evidence TEXT,
    recommendation TEXT,
    source_tool TEXT NOT NULL,
    fingerprint TEXT,
    source_id TEXT,
    template_id TEXT,
    observed_at TEXT,
    created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now'))
);

CREATE TABLE IF NOT EXISTS scan_artifacts (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    job_id INTEGER NOT NULL REFERENCES scan_jobs(id) ON DELETE CASCADE,
    source_tool TEXT NOT NULL,
    content_hash TEXT NOT NULL,
    payload TEXT NOT NULL,
    payload_format TEXT NOT NULL CHECK (payload_format IN ('json', 'text')),
    status TEXT NOT NULL CHECK (status IN ('complete', 'partial', 'corrupt')),
    metadata TEXT NOT NULL DEFAULT '{}',
    captured_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now')),
    UNIQUE(job_id, source_tool, content_hash)
);
CREATE INDEX IF NOT EXISTS idx_artifacts_job ON scan_artifacts(job_id);
CREATE INDEX IF NOT EXISTS idx_findings_target ON normalized_findings(target_id);
CREATE INDEX IF NOT EXISTS idx_jobs_target ON scan_jobs(target_id);

CREATE TABLE IF NOT EXISTS finding_observations (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    finding_id INTEGER NOT NULL REFERENCES normalized_findings(id) ON DELETE CASCADE,
    job_id INTEGER REFERENCES scan_jobs(id) ON DELETE SET NULL,
    severity TEXT NOT NULL CHECK (severity IN ('Critical', 'High', 'Medium', 'Low', 'Info')),
    observed_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now'))
);
CREATE INDEX IF NOT EXISTS idx_finding_observations_finding ON finding_observations(finding_id, observed_at);

CREATE TABLE IF NOT EXISTS remediation_tasks (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    finding_id INTEGER NOT NULL UNIQUE REFERENCES normalized_findings(id) ON DELETE CASCADE,
    status TEXT NOT NULL DEFAULT 'open' CHECK (status IN ('open', 'in_progress', 'blocked', 'resolved', 'accepted')),
    assignee TEXT NOT NULL DEFAULT '',
    due_date TEXT,
    notes TEXT NOT NULL DEFAULT '',
    created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now')),
    updated_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now'))
);
CREATE INDEX IF NOT EXISTS idx_remediation_status_due ON remediation_tasks(status, due_date, id);

CREATE TABLE IF NOT EXISTS remediation_sla_policies (
    severity TEXT PRIMARY KEY CHECK (severity IN ('Critical', 'High', 'Medium', 'Low', 'Info')),
    days INTEGER NOT NULL CHECK (days BETWEEN 1 AND 3650),
    updated_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now'))
);
INSERT OR IGNORE INTO remediation_sla_policies(severity, days) VALUES
    ('Critical', 7), ('High', 14), ('Medium', 30), ('Low', 90), ('Info', 180);

CREATE TABLE IF NOT EXISTS remediation_history (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    task_id INTEGER NOT NULL REFERENCES remediation_tasks(id) ON DELETE CASCADE,
    finding_id INTEGER NOT NULL,
    event_type TEXT NOT NULL CHECK (event_type IN ('created', 'updated')),
    old_status TEXT,
    new_status TEXT NOT NULL,
    old_assignee TEXT,
    new_assignee TEXT NOT NULL,
    old_due_date TEXT,
    new_due_date TEXT,
    changed_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now'))
);
CREATE INDEX IF NOT EXISTS idx_remediation_history_task ON remediation_history(task_id, id);

CREATE TABLE IF NOT EXISTS remediation_trend_snapshots (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    start_date TEXT,
    end_date TEXT,
    report_json TEXT NOT NULL,
    created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now'))
);
CREATE INDEX IF NOT EXISTS idx_remediation_trend_snapshots_created ON remediation_trend_snapshots(created_at);

CREATE TABLE IF NOT EXISTS remediation_verifications (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    task_id INTEGER NOT NULL REFERENCES remediation_tasks(id) ON DELETE CASCADE,
    outcome TEXT NOT NULL CHECK (outcome IN ('pending', 'verified', 'rejected')),
    evidence TEXT NOT NULL DEFAULT '',
    notes TEXT NOT NULL DEFAULT '',
    verified_by TEXT NOT NULL DEFAULT '',
    created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now'))
);
CREATE INDEX IF NOT EXISTS idx_remediation_verifications_task ON remediation_verifications(task_id, id);


CREATE TABLE IF NOT EXISTS risk_intelligence_alerts (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    alert_key TEXT NOT NULL UNIQUE,
    alert_type TEXT NOT NULL CHECK (alert_type IN ('target_finding_growth', 'recurring_finding', 'sla_backlog')),
    severity TEXT NOT NULL CHECK (severity IN ('info', 'warning', 'high', 'critical')),
    title TEXT NOT NULL,
    explanation TEXT NOT NULL,
    details_json TEXT NOT NULL DEFAULT '{}',
    status TEXT NOT NULL DEFAULT 'open' CHECK (status IN ('open', 'acknowledged', 'resolved')),
    first_seen TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now')),
    last_seen TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now')),
    acknowledged_by TEXT NOT NULL DEFAULT '',
    acknowledged_at TEXT
);
CREATE INDEX IF NOT EXISTS idx_risk_alert_status ON risk_intelligence_alerts(status, last_seen);

CREATE TABLE IF NOT EXISTS risk_intelligence_config (
    id INTEGER PRIMARY KEY CHECK (id = 1),
    config_json TEXT NOT NULL,
    updated_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now'))
);

CREATE TABLE IF NOT EXISTS risk_intelligence_rules (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT NOT NULL COLLATE NOCASE UNIQUE,
    description TEXT NOT NULL DEFAULT '',
    config_json TEXT NOT NULL,
    enabled INTEGER NOT NULL DEFAULT 1 CHECK (enabled IN (0,1)),
    created_by TEXT NOT NULL,
    updated_by TEXT NOT NULL,
    created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now')),
    updated_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now'))
);
CREATE TABLE IF NOT EXISTS risk_intelligence_rule_audit (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    rule_id INTEGER NOT NULL REFERENCES risk_intelligence_rules(id) ON DELETE CASCADE,
    action TEXT NOT NULL CHECK (action IN ('created','updated','enabled','disabled','rolled_back')),
    actor TEXT NOT NULL,
    before_json TEXT,
    after_json TEXT NOT NULL,
    created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now'))
);
CREATE INDEX IF NOT EXISTS idx_risk_rule_audit_rule ON risk_intelligence_rule_audit(rule_id, id DESC);

CREATE TABLE IF NOT EXISTS risk_intelligence_rule_versions (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    rule_id INTEGER NOT NULL REFERENCES risk_intelligence_rules(id) ON DELETE CASCADE,
    version_number INTEGER NOT NULL,
    snapshot_json TEXT NOT NULL,
    actor TEXT NOT NULL,
    created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now')),
    UNIQUE(rule_id, version_number)
);
CREATE INDEX IF NOT EXISTS idx_risk_rule_versions ON risk_intelligence_rule_versions(rule_id, version_number DESC);

CREATE TABLE IF NOT EXISTS risk_intelligence_rule_governance (
    rule_id INTEGER PRIMARY KEY REFERENCES risk_intelligence_rules(id) ON DELETE CASCADE,
    active_version_number INTEGER NOT NULL DEFAULT 1,
    approved_version_number INTEGER,
    approved_by TEXT,
    approved_at TEXT,
    locked INTEGER NOT NULL DEFAULT 0 CHECK (locked IN (0,1)),
    updated_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now'))
);
CREATE TABLE IF NOT EXISTS risk_intelligence_governance_audit (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    rule_id INTEGER NOT NULL REFERENCES risk_intelligence_rules(id) ON DELETE CASCADE,
    action TEXT NOT NULL,
    actor TEXT NOT NULL,
    details_json TEXT NOT NULL DEFAULT '{}',
    created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now'))
);
CREATE INDEX IF NOT EXISTS idx_risk_governance_audit_rule ON risk_intelligence_governance_audit(rule_id, id DESC);

CREATE TABLE IF NOT EXISTS risk_intelligence_policy_evaluations (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    evaluated_by TEXT NOT NULL,
    summary_json TEXT NOT NULL,
    result_json TEXT NOT NULL,
    created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now'))
);
CREATE INDEX IF NOT EXISTS idx_risk_policy_evaluations_created ON risk_intelligence_policy_evaluations(id DESC);

CREATE TABLE IF NOT EXISTS risk_policy_evidence (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    evaluation_id INTEGER NOT NULL,
    created_by TEXT NOT NULL,
    snapshot_json TEXT NOT NULL,
    sha256 TEXT NOT NULL,
    created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now'))
);
CREATE INDEX IF NOT EXISTS idx_risk_policy_evidence_evaluation ON risk_policy_evidence(evaluation_id, id DESC);

CREATE TABLE IF NOT EXISTS risk_policy_evidence_custody (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    event_type TEXT NOT NULL CHECK (event_type IN ('bundle_exported','bundle_verified','bundle_verification_failed')),
    actor TEXT NOT NULL,
    evidence_id INTEGER,
    evaluation_id INTEGER,
    bundle_sha256 TEXT NOT NULL,
    details_json TEXT NOT NULL,
    previous_hash TEXT,
    event_hash TEXT NOT NULL UNIQUE,
    created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now'))
);
CREATE INDEX IF NOT EXISTS idx_policy_evidence_custody_bundle ON risk_policy_evidence_custody(bundle_sha256, id DESC);

CREATE TABLE IF NOT EXISTS risk_policy_evidence_signing_keys (
    key_id TEXT PRIMARY KEY,
    public_key_b64 TEXT NOT NULL,
    algorithm TEXT NOT NULL DEFAULT 'Ed25519' CHECK (algorithm = 'Ed25519'),
    created_by TEXT NOT NULL,
    created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now')),
    revoked_by TEXT,
    revoked_at TEXT,
    revoked_reason TEXT NOT NULL DEFAULT ''
);
CREATE TABLE IF NOT EXISTS risk_policy_evidence_custody_checkpoints (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    checkpoint_id TEXT NOT NULL UNIQUE,
    event_count INTEGER NOT NULL CHECK (event_count >= 0),
    head_hash TEXT,
    key_id TEXT NOT NULL,
    algorithm TEXT NOT NULL DEFAULT 'Ed25519' CHECK (algorithm = 'Ed25519'),
    public_key_b64 TEXT NOT NULL,
    signature_b64 TEXT NOT NULL,
    actor TEXT NOT NULL,
    created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now')),
    payload_json TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_policy_custody_checkpoints_created ON risk_policy_evidence_custody_checkpoints(id DESC);

CREATE TABLE IF NOT EXISTS risk_policy_evidence_signing_key_audit (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    key_id TEXT NOT NULL,
    action TEXT NOT NULL CHECK (action IN ('registered','revoked')),
    actor TEXT NOT NULL,
    details_json TEXT NOT NULL DEFAULT '{}',
    created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now'))
);
CREATE INDEX IF NOT EXISTS idx_evidence_signing_key_audit_key ON risk_policy_evidence_signing_key_audit(key_id, id DESC);

CREATE TABLE IF NOT EXISTS risk_policy_exceptions (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    rule_id INTEGER NOT NULL REFERENCES risk_intelligence_rules(id) ON DELETE CASCADE,
    requested_by TEXT NOT NULL,
    reviewer TEXT NOT NULL,
    reason TEXT NOT NULL,
    expires_at TEXT NOT NULL,
    status TEXT NOT NULL DEFAULT 'pending' CHECK (status IN ('pending','approved','rejected','revoked','expired')),
    reviewed_by TEXT,
    reviewed_at TEXT,
    review_note TEXT NOT NULL DEFAULT '',
    created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now'))
);
CREATE INDEX IF NOT EXISTS idx_risk_policy_exceptions_rule ON risk_policy_exceptions(rule_id, id DESC);
CREATE INDEX IF NOT EXISTS idx_risk_policy_exceptions_expiry ON risk_policy_exceptions(status, expires_at);
CREATE TABLE IF NOT EXISTS risk_policy_exception_audit (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    exception_id INTEGER NOT NULL REFERENCES risk_policy_exceptions(id) ON DELETE CASCADE,
    action TEXT NOT NULL,
    actor TEXT NOT NULL,
    details_json TEXT NOT NULL DEFAULT '{}',
    created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now'))
);
CREATE TABLE IF NOT EXISTS risk_policy_retention_settings (
    id INTEGER PRIMARY KEY CHECK (id = 1),
    retention_days INTEGER NOT NULL DEFAULT 365 CHECK (retention_days BETWEEN 1 AND 3650),
    updated_by TEXT NOT NULL DEFAULT 'system',
    updated_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now'))
);
INSERT OR IGNORE INTO risk_policy_retention_settings(id,retention_days) VALUES(1,365);

CREATE TABLE IF NOT EXISTS risk_intelligence_comparison_history (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    rule_ids_json TEXT NOT NULL,
    summary_json TEXT NOT NULL,
    result_json TEXT NOT NULL,
    created_by TEXT NOT NULL,
    created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now'))
);
CREATE INDEX IF NOT EXISTS idx_risk_comparison_history_created ON risk_intelligence_comparison_history(id DESC);

CREATE TABLE IF NOT EXISTS comparison_history (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    before_job_id INTEGER NOT NULL REFERENCES scan_jobs(id) ON DELETE CASCADE,
    after_job_id INTEGER NOT NULL REFERENCES scan_jobs(id) ON DELETE CASCADE,
    schema_version INTEGER NOT NULL DEFAULT 1,
    summary_json TEXT NOT NULL,
    result_json TEXT NOT NULL,
    created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now')),
    UNIQUE(before_job_id, after_job_id),
    CHECK(before_job_id <> after_job_id)
);
CREATE INDEX IF NOT EXISTS idx_comparison_history_created ON comparison_history(created_at);

CREATE TABLE IF NOT EXISTS alert_policies (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT NOT NULL UNIQUE,
    severities_json TEXT NOT NULL,
    event_types_json TEXT NOT NULL,
    enabled INTEGER NOT NULL DEFAULT 1 CHECK (enabled IN (0, 1)),
    created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now'))
);
CREATE TABLE IF NOT EXISTS notification_events (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    policy_id INTEGER NOT NULL REFERENCES alert_policies(id) ON DELETE CASCADE,
    comparison_id INTEGER NOT NULL REFERENCES comparison_history(id) ON DELETE CASCADE,
    event_key TEXT NOT NULL UNIQUE,
    event_type TEXT NOT NULL CHECK (event_type IN ('added', 'reappeared', 'changed')),
    severity TEXT NOT NULL CHECK (severity IN ('Critical', 'High', 'Medium', 'Low', 'Info')),
    title TEXT NOT NULL,
    payload_json TEXT NOT NULL,
    status TEXT NOT NULL DEFAULT 'pending' CHECK (status IN ('pending', 'acknowledged', 'suppressed')),
    created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now')),
    updated_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now'))
);
CREATE INDEX IF NOT EXISTS idx_notification_events_status ON notification_events(status, id);
CREATE TABLE IF NOT EXISTS notification_dead_letters (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    event_id INTEGER NOT NULL UNIQUE REFERENCES notification_events(id) ON DELETE CASCADE,
    reason TEXT NOT NULL,
    attempts INTEGER NOT NULL,
    quarantined_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now')),
    resolved_at TEXT
);
CREATE INDEX IF NOT EXISTS idx_notification_dead_letters_open ON notification_dead_letters(resolved_at, id);

CREATE TABLE IF NOT EXISTS notification_deliveries (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    event_id INTEGER NOT NULL REFERENCES notification_events(id) ON DELETE CASCADE,
    destination_host TEXT NOT NULL,
    outcome TEXT NOT NULL CHECK (outcome IN ('sent', 'failed', 'skipped')),
    http_status INTEGER,
    attempt_count INTEGER NOT NULL DEFAULT 0,
    error TEXT,
    idempotency_key TEXT,
    created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now'))
);
CREATE INDEX IF NOT EXISTS idx_notification_deliveries_event ON notification_deliveries(event_id, id);
"""


@contextmanager
def connect(path: str | Path) -> Iterator[sqlite3.Connection]:
    db_path = Path(path)
    db_path.parent.mkdir(parents=True, exist_ok=True)
    connection = sqlite3.connect(db_path)
    connection.row_factory = sqlite3.Row
    connection.execute("PRAGMA foreign_keys = ON")
    try:
        yield connection
        connection.commit()
    except Exception:
        connection.rollback()
        raise
    finally:
        connection.close()


def initialize(path: str | Path) -> None:
    with connect(path) as connection:
        connection.executescript(SCHEMA)
        # Expand the rule-audit action constraint for databases created before Stage 40.
        audit_schema = connection.execute("SELECT sql FROM sqlite_master WHERE type='table' AND name='risk_intelligence_rule_audit'").fetchone()
        if audit_schema and "rolled_back" not in (audit_schema["sql"] or ""):
            connection.execute("ALTER TABLE risk_intelligence_rule_audit RENAME TO risk_intelligence_rule_audit_legacy")
            connection.execute("""CREATE TABLE risk_intelligence_rule_audit (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                rule_id INTEGER NOT NULL REFERENCES risk_intelligence_rules(id) ON DELETE CASCADE,
                action TEXT NOT NULL CHECK (action IN ('created','updated','enabled','disabled','rolled_back')),
                actor TEXT NOT NULL,
                before_json TEXT,
                after_json TEXT NOT NULL,
                created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now'))
            )""")
            connection.execute("INSERT INTO risk_intelligence_rule_audit(id,rule_id,action,actor,before_json,after_json,created_at) SELECT id,rule_id,action,actor,before_json,after_json,created_at FROM risk_intelligence_rule_audit_legacy")
            connection.execute("DROP TABLE risk_intelligence_rule_audit_legacy")
            connection.execute("CREATE INDEX IF NOT EXISTS idx_risk_rule_audit_rule ON risk_intelligence_rule_audit(rule_id, id DESC)")
        # Backfill a baseline immutable version for named rules that predate Stage 40.
        legacy_rules = connection.execute("SELECT r.* FROM risk_intelligence_rules r LEFT JOIN risk_intelligence_rule_versions v ON v.rule_id=r.id WHERE v.id IS NULL").fetchall()
        for rule in legacy_rules:
            snapshot = {"name": rule["name"], "description": rule["description"], "config": json.loads(rule["config_json"]), "enabled": bool(rule["enabled"])}
            connection.execute("INSERT INTO risk_intelligence_rule_versions(rule_id,version_number,snapshot_json,actor) VALUES(?,1,?,?)", (rule["id"], json.dumps(snapshot, sort_keys=True), rule["updated_by"] or rule["created_by"] or "migration"))
        connection.execute("INSERT OR IGNORE INTO risk_intelligence_rule_governance(rule_id, active_version_number) SELECT r.id, COALESCE((SELECT MAX(v.version_number) FROM risk_intelligence_rule_versions v WHERE v.rule_id=r.id),1) FROM risk_intelligence_rules r")
        # Backward-compatible migration for databases created by earlier stages.
        target_columns = {row["name"] for row in connection.execute("PRAGMA table_info(targets)")}
        if "criticality" not in target_columns:
            connection.execute("ALTER TABLE targets ADD COLUMN criticality TEXT NOT NULL DEFAULT 'medium'")
        columns = {row["name"] for row in connection.execute("PRAGMA table_info(normalized_findings)")}
        if "fingerprint" not in columns:
            connection.execute("ALTER TABLE normalized_findings ADD COLUMN fingerprint TEXT")
        for column in ("source_id", "template_id", "observed_at"):
            if column not in columns:
                connection.execute(f"ALTER TABLE normalized_findings ADD COLUMN {column} TEXT")
        event_columns = {row["name"] for row in connection.execute("PRAGMA table_info(notification_events)")}
        event_migrations = {
            "lease_owner": "TEXT",
            "lease_until": "TEXT",
            "delivery_attempts": "INTEGER NOT NULL DEFAULT 0",
            "next_attempt_at": "TEXT",
            "last_delivery_error": "TEXT",
        }
        for column, declaration in event_migrations.items():
            if column not in event_columns:
                connection.execute(f"ALTER TABLE notification_events ADD COLUMN {column} {declaration}")
        connection.execute("CREATE INDEX IF NOT EXISTS idx_notification_queue_due ON notification_events(status, next_attempt_at, lease_until, id)")
        delivery_columns = {row["name"] for row in connection.execute("PRAGMA table_info(notification_deliveries)")}
        if "idempotency_key" not in delivery_columns:
            connection.execute("ALTER TABLE notification_deliveries ADD COLUMN idempotency_key TEXT")
        connection.execute("CREATE INDEX IF NOT EXISTS idx_notification_delivery_idempotency ON notification_deliveries(idempotency_key) WHERE idempotency_key IS NOT NULL")
        connection.execute("CREATE UNIQUE INDEX IF NOT EXISTS idx_findings_fingerprint ON normalized_findings(fingerprint) WHERE fingerprint IS NOT NULL")

        # Stage 55: durable scanner-job lease and retry metadata.
        scan_columns = {row["name"] for row in connection.execute("PRAGMA table_info(scan_jobs)")}
        scan_migrations = {
            "lease_owner": "TEXT",
            "lease_until": "TEXT",
            "attempt_count": "INTEGER NOT NULL DEFAULT 0",
            "max_attempts": "INTEGER NOT NULL DEFAULT 3",
            "cancel_requested_at": "TEXT",
        }
        for column, declaration in scan_migrations.items():
            if column not in scan_columns:
                connection.execute(f"ALTER TABLE scan_jobs ADD COLUMN {column} {declaration}")
        connection.execute("CREATE INDEX IF NOT EXISTS idx_scan_jobs_claim ON scan_jobs(status, lease_until, created_at, id)")
        # Day02 additive migration executes inside the same DB connection.
        from cybersec.day02 import apply_migration
        apply_migration(connection)

