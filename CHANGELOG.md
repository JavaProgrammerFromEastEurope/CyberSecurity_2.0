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
