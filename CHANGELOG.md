## 2.44.0 — Stage 64: Ubuntu 26.10 runtime inventory and blocked production admission

- Reconciled divergent `chat-stage63-v2.43.0` and `prework_cybersecurity`
  Git heads without altering either version; documented incompatible APIs.
- Added read-only Ubuntu 26.10 Python/OpenSSL/systemd/AppArmor/cgroup/UID
  compatibility inventory; `cybersec host-preflight` returns 3/NO-GO.
- Added mandatory development-code production-mode denial at JobRunner,
  scanner-worker, ZAP, Nuclei, sqlmap execution entrypoints. No production
  scanner authority is minted; same-UID/legacy MAC confinement remains unproven.
- Added PID starttime/cgroup observation and cgroup.events read-only helpers.
- Added independent systemd manager lifecycle candidate (disabled by default)
  with `KillMode=control-group`, `ExecStartPre` fail-closed, and AppArmor
  acceptance contract; no unit was installed/enabled on this build host.
- Retained Stage 61 PDF, Stage 62 process supervision and Stage 63 worker
  cancellation, API/CLI, SQLite schema and prior evidence.
- Added Python-only local and Ubuntu opt-in integration tests. No external
  security scanner or Ubuntu service deployment was executed.
- **Production: BLOCKED/NO-GO** pending Ubuntu 26.10 and independent OS-MAC,
  cgroup, per-attempt authority and recovery proofs.
- Hardened SQLmap approval entrypoint: blocked production attempts refuse before
  repository one-time permit claim; dedicated regression test prevents reversion.

## 2.43.0 — Stage 63

- Worker-owned Nuclei subprocess runs are now obligatorily process-supervised with cooperative cancellation on persistent cancel request, lease loss, SIGTERM/SIGINT, and lost fencing token.
- CLI worker installs/restores signal handlers and propagates stop to supervised process groups; interrupted external work remains manual-recovery-only.
- Bounded SIGTERM/SIGKILL cleanup to avoid indefinitely waiting for pipes held by escaping descendants; not a full tree-containment guarantee.
- New safe Python process tests, SQLite lifecycle tests, gated Ubuntu Server integration fixtures, audit evidence and strict-regression diagnostics. No real scanners executed.
- **BLOCKED / NO-GO** until independent Ubuntu systemd/cgroup proof and authorized end-to-end tests.

## 2.42.0 — Stage 62

- Opt-in POSIX process group supervision with SIGTERM/SIGKILL and bounded timeout; no external scanner execution in tests.
- Resource closure regression fix in legacy artifact migration test.
- Ubuntu Server integration plan and explicit NO-GO limitations.

## 2.41.0 — Stage 61
- Offline A4 PDF report with Unicode text, executive/technical profiles, evidence, recommendations, appendix and SHA-256 manifest.
- No scanner execution in PDF pipeline.

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


## 2.45.0 — Stage 65: OS-enforced isolation contracts & durable recovery (BLOCKED/NO-GO)

- Added isolated `cybersec.stage65` modules for canonical Ed25519 per-attempt
  permits, immutable argv digests, expected UID/scope/generation/time validation.
- Added one-shot SQLite witness-intent journal, independent Unix socket witness
  CAS protocol and crash/replay/rollback recovery logic.
- Added root-delegated cgroup v2 pre-exec trampoline, pidfd/starttime checks,
  `cgroup.kill` cleanup, cold orphan recovery and peer-credential broker API.
- Added five-UID isolation roles (broker + worker/attester/witness/publisher),
  root-owned config requirements and AppArmor/MAC/systemd unit candidates.
- Added `cybersec host65-preflight` returning 3/BLOCKED/NO-GO, real SIGKILL
  Python-only tests and opt-in Ubuntu Server 26.10 integration tests.
- Kept Stage 64 production scan denial and Stage 61 PDF, Stage 62/63 worker,
  Stage 64 APIs/SQLite/evidence unchanged. **No Ubuntu acceptance and no GO.**
