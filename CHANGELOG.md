## 2.43.0 — Stage 63: Independent Linux Lab E2E & Mandatory MAC Confinement (fail-closed candidate)

- Added read-only independent service and kernel LSM audit for four separate UIDs, systemd service identities, `/proc` PID/starttime and cgroup evidence.
- Added signed recovery receipt verifier bound to exact job/attempt, boot ID, checkpoint digest and monotonic counter progression. Without independent CAS/TPM authority the recovery gate always rejects.
- Added safe local negative E2E, process lifecycle and fail-closed test suite; production network scanners remain disabled without independent admission.
- Added kernel MAC confinement requirements and external acceptance test plan; did not install policies or claim a real MAC/LSM proof.
- **Production remains BLOCKED/NO-GO**; no active external scanning was executed on the development host.

# Stage 62 — 2.42.0 (OS-Enforced Containment Candidate)

- Added fail-closed cgroup v2 execution gate and blocked trampoline, exact PID
  starttime / cgroup checks, kernel cgroup.kill cleanup and population checks.
- Added independent Ed25519 signed per-attempt loopback lab tickets;
  production Nuclei refuses unsigned direct invocation.
- Blocked production ZAP remote-daemon and SQLmap execution paths.
- Added read-only host audit, proposed systemd unit and security contracts.
- No full OS-enforced legacy confinement, production admission or live network
  scan is claimed. All prior versions, schemas, evidence and API remain.

## 2.41.0 — Stage 61: Local Scanner Process Supervision
- Supervised Nuclei worker subprocesses with bounded output/deadline, POSIX process-group SIGTERM/SIGKILL escalation, no shell, and no implicit retries.
- Scan worker observes cancel, revoked/expired lease, and stop_event during execution; CLI handles SIGTERM/SIGINT.
- Attempt token is now optional and enforced for worker finalization to prevent recycled-worker-id stale writes; existing API remains available.
- ZAP passive polling cooperatively exits on cancellation but does not terminate the shared daemon.
- Updated Stage 60-to-61 roadmap reconciliation and documented NO-GO for external process, cgroup and customer production acceptance.
- Strict regression and raw run evidence accompany release artifacts; earlier failed/incomplete runs are retained.

Stage 60: conservative scanner execution recovery policy. See docs/STAGE_60_EXECUTION_RECOVERY.md.
Stage 59: atomic worker result commit with attempt fencing. See docs/STAGE_59_ATOMIC_RESULT_COMMIT.md.

## 2.36.0 — Stage 56
- Added opt-in, bounded sqlmap candidate-confirmation adapter with fail-closed scope checks and mocked tests.
- No default registry or worker activation until persistent provenance/authorization gates exist.

## Stage 55 — Durable Scanner Job Execution Foundation (2.35.0)

- Added durable scan-job leases, atomic claims, bounded retry attempts and stale-lease recovery.
- Added dedicated scanner worker process with lease heartbeat and graceful stop behavior.
- Added lease-owner completion checks and persisted cancellation requests.
- Kept notification workers separate; API job creation remains metadata-only.
- Added Stage 55 concurrency, recovery, ownership and worker execution tests.

## Stage 54 — Architecture & Requirements Baseline (2.34.0)

- Replaced stale architecture documentation with a source-oriented description of the Stage 53 implementation.
- Added requirements traceability with explicit implemented/partial/missing/not-externally-verified states.
- Added a measurable integration plan and acceptance gates for Stages 55–60.
- Updated README and roadmap. No runtime code or database schema changed.

## Stage 53 — Evidence Revalidation History and Tamper-Evident Reports (2.33.0)

- Added an offline JSONL hash chain for continuous evidence revalidation reports, with sequence numbers, report digests, predecessor links, and entry digests.
- Added append protection: an existing chain must verify before another report can be appended; writes use atomic replacement.
- Added standalone chain verification and portable audit-package export/verification commands; no database initialization is required.
- Verification detects report edits, entry edits, deletion, insertion, and reordering within the supplied chain. A separately preserved chain head/hash is still needed to detect truncation against a trusted external reference; hashes do not authenticate the author.

## Stage 52 — Continuous Trust Monitoring and Evidence Revalidation (2.32.0)

- Added offline comparison of two independently signed trust-registry snapshots, reporting added/removed keys, key-material changes, revocation transitions, registration timestamp changes, and audit-history non-monotonicity.
- Added batch revalidation of top-level evidence bundle JSON files against a supplied, externally anchored signed trust snapshot.
- Reports per-file status transitions (`new`, `unchanged`, `trust_lost`, `trust_restored`, or `validation_error`) compared with an optional prior report.
- Added `cybersec evidence revalidate` and `cybersec evidence trust-diff`; both can write portable JSON reports and run before database initialization.
- Documents limits: snapshot-only visibility, no guarantee that an operator recorded every real-world event, and prior reports are comparison inputs rather than authenticated historical truth.

## Stage 51 — Trust-Aware Evidence Validation and Audit Continuity (2.31.0)

- Added offline verification that binds Ed25519 evidence-bundle signatures to public keys in a separately signed trust-registry snapshot.
- Evaluates key creation and revocation timestamps relative to the bundle manifest timestamp; a cryptographically valid signature from a key revoked before signing is not trusted.
- Produces a unified JSON audit report for registry integrity, evidence integrity/signature, signer trust, and basic audit-event continuity.
- Added `cybersec evidence audit-portable` CLI command; verification does not initialize the application database.
- Explicitly documents limitations around stale snapshots, external append-only audit proof, and evidentiary truth.
- Retained Stage 50 trust snapshot export and standalone verification.

## Stage 50 — Trust Registry Snapshots and Portable Audit Reports (2.30.0)

- Added signed portable snapshots of registered Ed25519 public keys, including revoked keys, and their registration/revocation audit history.
- Added offline verification and a portable audit report with explicit external trust anchor.
- Export requires a matching active registered signing key; private key material is not included in output.
- Added CLI commands `evidence trust-snapshot-export` and `evidence trust-snapshot-verify`.
- Retained Stage 49 offline evidence bundle verification and atomic key rotation.

## 2.38.0 — Stage 58
- Hardened cancellation lease renewal, terminal cancelled recovery, and stale-owner checks.
- Added five lease-safety regression tests and documentation.
