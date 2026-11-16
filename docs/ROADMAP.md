- Stage 51: Trust-aware offline evidence validation against signed trust-registry snapshots, time-aware key revocation assessment, and unified portable audit reports.
- Stage 41: Risk Intelligence Governance—active versions, before/after outcome previews, approvals, locks, audit trail, and integrity-checked import/export.
- Stage 40: immutable risk-rule versions, audited rollback, and persistent comparison history.

# Roadmap

- Stage 1: project skeleton, target authorization acknowledgement, SQLite and CLI.
- Stage 2: job lifecycle and adapter registry with offline demo adapter.
- Stage 3: passive-only OWASP ZAP adapter.
- Stage 4: conservative Nuclei adapter.
- Stage 5: finding normalization and deduplication.
- Stage 6: taxonomy and explainable internal risk triage.
- Stage 7: self-contained HTML report.
- Stage 8: report filters, executive/technical profiles, project and assessment-window metadata.
- Stage 9: structured raw-result retention and richer finding provenance, preserving conservative confidence semantics. (Implemented in 0.9.0.)
- Stage 10: resilient ingestion pipeline with explicit import/replay commands, richer artifact search, and report provenance references. (Implemented in 1.0.0.)
- Stage 11: ingestion validation summaries, Nuclei JSONL support, and export integrity manifests with verification. (Implemented in 1.1.0.)
- Stage 12: offline comparison of retained results across jobs, with added/resolved/unchanged/severity-changed classifications. (Implemented in 1.2.0.)
- Later: optional PDF generation, API/UI, authentication, hardened deployment, integration testing, and release packaging.

The roadmap is iterative; passing unit tests does not substitute for authorized end-to-end testing against a controlled lab target.


## Stage 13 delivered
- Persist comparison snapshots and summary metadata in SQLite.
- List/export history and inspect an individual saved comparison.
- Keep comparison operations offline and deterministic for the same retained artifacts.

## Next
- Add trend summaries across multiple saved comparisons, including recurring/resurfaced fingerprints.
- Add self-contained HTML history reports and explicit retention policies.

## Stage 15 delivered

- Local alert policies for severity and comparison-event categories.
- Persistent idempotent event queue with review/suppression states.
- External delivery integrations remain out of scope and disabled by default.


## Stage 16 completed
- Explicitly confirmed webhook delivery over HTTPS, payload preview, bounded retries, redirect refusal, and local delivery audit log.

## Next: Stage 17
- Add configurable payload redaction, delivery idempotency keys, and dead-letter/retry management with no automatic sending by default.


## Stage 17 completed
- Sensitive-data redaction for webhook payloads.
- Optional webhook hostname allowlist and local configuration validation.
- Idempotency key generation and storage.
- Explicitly confirmed retry for failed deliveries.

## Next: Stage 18
- Delivery queue leases and safe concurrent workers.
- Configurable backoff policy and clearer permanent/transient error classification.
- Secret-safe audit exports and delivery metrics.


## Completed in Stage 19
- Long-running opt-in notification worker with graceful stop behavior.
- Dead-letter quarantine after bounded failed attempts, plus explicit operator resolution.
- Queue diagnostics for quarantined events.

## Stage 20 delivered

- Local-only queue metrics and health diagnostics.
- Structured JSON worker logs with payload omission.
- Regression test for concurrent queue claims.

Potential next stage: configurable log destinations/rotation, latency percentiles from persisted attempt timestamps, and a documented process supervisor deployment example.


## Stage 24
- Detail endpoints for individual targets, jobs, and findings.
- Correlation IDs and machine-readable error codes.
- Basic per-client rate limiting and JSON content-type enforcement.

## Stage 27

A self-contained read-only browser dashboard is served at `/dashboard`. Future UI changes should preserve loopback-only binding, explicit authorization for target registration, and the separation between queued job metadata and scanner execution.


## Stage 32 — Remediation planning (2.12.0)
- Persistent per-finding remediation tasks with lifecycle status, assignee, due date, and notes.
- Overdue detection and summary metrics, with authenticated API and dashboard controls.
- Resolution/accepted statuses are excluded from overdue counts; no external actions are performed.


## Stage 35 — Remediation performance reporting
- Added date-filtered average/median resolution time, SLA compliance, verification coverage, and breakdowns by severity, assignee and target.
- Added authenticated JSON/CSV exports and dashboard date controls.
- Next: optional trend snapshots and comparison between reporting periods while preserving clear date-basis definitions.


## Stage 37 completed: Risk Intelligence

Persistent explainable alerts now cover target finding growth, repeated observation after a resolved remediation task, and overdue remediation backlog. Analysts can acknowledge alerts; later refreshes resolve alerts when the underlying signal is no longer detected.


## Stage 42 — Risk Intelligence Policy Enforcement (2.22.0)

- Inspect approval freshness and detect live configuration drift from immutable active-version snapshots.
- Evaluate only enabled rules whose active version remains approved and matches the current configuration.
- Persist policy evaluation summaries and provide protected API history/detail routes.
- Keep evaluation preview-only: no alert persistence, scanner execution, or outbound network activity.

## Stage 43 — Policy Exceptions and Review Workflow (2.23.0)

- Time-bounded exception requests require a reason, assigned reviewer, and separation of requester/reviewer.
- Assigned reviewer can approve or reject; pending or approved exceptions can be revoked with a reason. Expired pending/approved exceptions are marked expired and audited.
- Exceptions are governance records only; they never bypass the approved-active-version enforcement gate.
- Policy evaluation history retention is configurable (1–3650 days); pruning is dry-run by default and requires explicit deletion mode.
- All exception and retention workflows have protected loopback API routes.

### Completed: Stage 44 — Policy Evidence and Compliance Reporting

- Build reproducible compliance snapshots that reference evaluation IDs and rule-version hashes.
- Add machine-readable exception and policy compliance exports, while keeping audit history immutable and secrets excluded.


## Stage 44 — Policy Evidence and Compliance Reporting (2.24.0)

Create reproducible, immutable compliance snapshots tied to policy evaluation IDs and exact active/approved rule versions. Verify snapshots with SHA-256, redact secret-like fields before persistence, and export JSON/CSV reports only after integrity validation. Evidence records remain available if evaluation history is later pruned.

Next: Stage 45 — Evidence Verification and Audit Bundles: export a self-contained bundle with evidence digest, referenced version metadata, verification result, and machine-readable manifest.


## Stage 45 — Evidence Verification and Audit Bundles (2.25.0)

- Export self-contained evidence bundles with a machine-readable manifest, snapshot digest, bundle digest, and verification status.
- Optional HMAC-SHA256 shared-key authentication and non-mutating bundle verification.
- Import path validates content but does not persist external bundles.
- HMAC provides shared-secret authentication, not asymmetric signatures; public-key signing can be introduced later with a carefully managed key lifecycle.

Next: Stage 46 — Evidence Chain of Custody: append-only export/verification events, bundle provenance fields, and explicit verifier identity while keeping verification non-mutating with respect to the evidence snapshot.


## Stage 46 completed — Evidence Chain of Custody

Implemented source provenance in bundle manifests, custody event logging, chained event hashes, replay indicators, and chain verification endpoints. Stage 47 added optional asymmetric signatures (e.g. Ed25519) with explicit key IDs and trust configuration; HMAC is not a substitute for public-key signatures.


## Stage 47 completed — Asymmetric Evidence Signatures

Evidence bundles support Ed25519 signatures. Trusted public keys have unique IDs, revocation state, and audit events. Verification rejects unknown and revoked keys while legacy HMAC bundles remain supported.

Completed: Stage 49 — atomic key rotation and offline verification of evidence bundles and signed custody checkpoints.


## Stage 48 completed — Signed Custody Checkpoints

Added Ed25519-signed custody checkpoints that anchor a specific chain prefix using its event count and head hash. Checkpoints can be verified against an independently supplied public key and retained outside the database to detect rewriting of the anchored prefix. The embedded public key is not a trust anchor by itself.


## Stage 49 completed — Key Lifecycle and Offline Evidence Verification

- Added offline verification for portable bundles and signed custody checkpoints using a separately supplied trusted Ed25519 public key.
- Added atomic key rotation with registration/revocation audit records.
- Offline checkpoint signature verification is separate from checking the corresponding event prefix; exported custody events are needed for the latter.
- HMAC remains a shared-secret mechanism and is not validated by the public-key-only offline verifier.

Next: Stage 50 — signed key-registry snapshots, trusted-key distribution metadata, and portable full-chain verification reports.


## Stage 50 — Trust Registry Snapshots and Portable Audit Reports

- Signed portable snapshot of registered public signing keys, including revoked keys, and key registration/revocation audit events.
- Export signer must be an active registered key whose public key matches the supplied Ed25519 private key.
- Offline verification validates canonical snapshot SHA-256 and Ed25519 signature against an explicitly supplied external public key.
- Portable report includes verification status, key history, and audit events; no private key is exported and verification does not initialize the application database.
- CLI: `evidence trust-snapshot-export` and `evidence trust-snapshot-verify`.


## Stage 54 — Architecture & Requirements Baseline (2.34.0)

- Replaced the stale early-stage architecture overview with a source-oriented architecture baseline.
- Added a requirements traceability matrix with implemented, partial, missing and externally unverified statuses.
- Added measurable integration plans and acceptance criteria for Stages 55–60.
- No runtime behavior or database schema changed.

## Next milestones

See `docs/INTEGRATION_PLAN.md`. Stage 55 is the durable scanner-job execution foundation. Do not start dependent scanner integrations until its concurrency, crash-recovery and cancellation gates pass.


## Stage 55 — Durable Scanner Job Execution Foundation (2.35.0)

Implemented SQLite-backed atomic scan-job claims, worker leases and heartbeats, bounded retries, expired-lease recovery, a dedicated scanner worker CLI, and persisted cancellation requests. See `STAGE_55_SCANNER_WORKERS.md`. Running external scanner processes are not yet forcibly interrupted by cancellation.

## Stage 61 — Local Scanner Process Supervision (v2.41.0)

- Verified local process-group supervision for **worker-owned** Nuclei launches: bounded runtime/output, persisted cancel and lease-loss polling, SIGTERM → SIGKILL escalation.
- Added optional lease-attempt fencing on worker error completion and a SIGTERM/SIGINT shutdown path for the scanner-worker CLI.
- Kept ZAP passive-only; its cancellation is cooperative and cannot guarantee termination of the separate ZAP daemon.
- Preserved Stage 60 failed/manual recovery policy for uncertain external actions. No automatic restart of externally-effectful work.
- Retained known gaps in `docs/INTEGRATION_PLAN.md`: its Stage 55–60 items were acceptance *goals*, not proof that PDF, RBAC, scanner-enabled lab E2E or the whole release-candidate program were delivered by Stage 60.
- Details: `docs/STAGE_61_PROCESS_SUPERVISION.md`.

**Next milestone:** independently isolated, authorized end-to-end process containment and worker restart tests; no production deployment claim without cgroup v2/LSM enforcement and observed external scanner termination.
