# Integration Plan — Stages 55–60

This plan follows the Stage 54 requirements baseline. It is intentionally outcome-driven: each stage has an observable acceptance gate. Stage numbers are milestones, not a target count.

## Stage 55 — Durable Scanner Job Execution Foundation

**Goal:** Separate scan execution from API request handling and from notification delivery.

Scope:
- Durable scan-job queue with atomic claim/lease semantics, owner, lease expiry and bounded retry policy.
- Dedicated scanner worker process with graceful shutdown.
- Persisted state transitions, timestamps, attempt count and sanitized error details.
- Cancellation and stale-lease recovery.
- Re-check target authorization and adapter availability immediately before execution.
- Preserve synchronous local execution only as an explicitly documented mode if compatibility requires it.

Acceptance:
- Two concurrent workers cannot claim the same active lease.
- Worker crash after claim is recoverable after lease expiry.
- Cancellation prevents a not-yet-started scan and is observed by cooperative adapters.
- API job creation remains non-blocking and does not run scanners in the request process.
- Notification queue behavior remains isolated and unchanged.
- Unit, concurrency and recovery tests pass.

## Stage 56 — Bounded sqlmap Confirmation Adapter

**Goal:** Confirm only eligible candidate findings, not run unrestricted database extraction.

Scope:
- Accept only a registered, currently authorized target and a candidate URL/parameter from an existing finding.
- Enforce exact-origin and path/scope policy before process launch and on any reported result.
- Conservative request/risk/level settings, strict timeout, request/concurrency budgets and cancellation.
- No database dumps, table extraction, credential dumping, user enumeration or destructive actions.
- Record command profile, tool version, sanitized output and provenance.

Acceptance:
- Out-of-scope URLs and arbitrary user-supplied command options are rejected.
- No process starts without current authorization and a qualifying candidate finding.
- Fake-process tests cover timeout, cancellation, non-zero exit, malformed output and positive/negative confirmation.
- Positive confirmation requires an unambiguous supported signal; uncertain outcomes remain inconclusive.

## Stage 57 — Explicit ZAP Scan Profiles

**Goal:** Keep passive-only behavior as the default while making any active phase explicit and auditable.

Scope:
- Named profiles for passive baseline, Spider, Ajax Spider and Active Scan.
- Active profiles disabled by default and require a separate explicit authorization record/approval.
- Per-profile scope, rate, duration, rule policy, timeout and cancellation.
- Record profile and authorization evidence in job/artifact provenance.

Acceptance:
- Default profile never invokes Spider, Ajax Spider or Active Scan.
- Active profile cannot run without explicit authorization and scope validation.
- Redirects and out-of-origin results remain constrained.
- Tests assert which ZAP endpoints are and are not called for each profile.

## Stage 58 — Explainable Cross-tool Correlation

**Goal:** Correlate observations without discarding their original evidence.

Scope:
- Stable vulnerability taxonomy and normalized origin/path/parameter identity.
- Correlation reason codes and confidence.
- Separate states such as candidate, corroborated, confirmed and conflicting.
- Preserve every source tool, source ID, raw artifact reference and observation time.
- Keep fingerprint deduplication distinct from semantic correlation.

Acceptance:
- Deterministic fixtures cover same issue from multiple tools, similar-but-distinct issues, parameter mismatch and conflicting severity.
- Every merge/correlation has a machine-readable reason.
- Original evidence and source provenance remain recoverable.

## Stage 59 — Client Report Package

**Goal:** Produce consistent, portable customer deliverables.

Scope:
- PDF report generated from the same normalized report model as HTML.
- Scope, authorization context, methodology, test limitations, executive summary, findings, severity rationale, evidence, remediation and retest status.
- Content hashes and manifest for attached evidence.
- Clear handling of sensitive evidence and redaction.

Acceptance:
- HTML and PDF agree on finding counts, identifiers and severity.
- PDF generation is deterministic enough for regression testing, with metadata variability handled explicitly.
- Secret-like values are excluded/redacted according to policy.
- Package can be verified offline and includes no private signing keys.

## Stage 60 — Controlled End-to-End Release Candidate

**Goal:** Demonstrate the complete product in an isolated, authorized lab.

Scope:
- Scanner-enabled isolated Compose/deployment topology.
- CI unit, integration, security and compatibility suites.
- Disposable lab target with documented authorization and bounded test profile.
- Performance, worker recovery, cancellation, backup/restore and release rollback checks.
- Release checklist, operator guide and known-limitations register.

Acceptance:
- A target can be registered, authorized, scanned asynchronously, normalized, correlated, reported and exported end-to-end.
- No out-of-scope request is observed in lab evidence.
- Worker crash/restart and cancellation scenarios pass.
- Deployment can be reproduced from documented instructions.
- All test results and environment versions are retained with the release candidate.

## Sequencing rule

Do not begin a dependent stage until its predecessor's acceptance tests pass. If a stage exposes a safety or data-integrity defect, fix it before adding another feature.

## Actual implementation reconciliation — Stage 61

The aspirational Stage 55–60 work packages above are a requirements baseline, **not an assertion of delivered scope**. The actual Stage 55–60 releases implemented durable leases, bounded sqlmap candidate checks, sqlmap approval, lease fencing, atomic result commit, and conservative external-scanner recovery. Items such as explicitly authorized active ZAP profiles, semantic correlation, PDF report equivalence, client-isolated release topology, and full authorized E2E were **not evidenced** in the Stage 60 source. Stage 61 improves local process supervision but does not close those independent product-acceptance gates. See `STAGE_61_PROCESS_SUPERVISION.md`.


## Stage 63 external host acceptance gate

No scanner shall execute in production until an independently measured Linux host demonstrates kernel MAC/LSM denies, actual writable cgroup delegation, four distinct UID roles, real service lifecycle/restart, replay-safe monotonic recovery and a per-attempt owner-authorized loopback lab. `stage63_host` exit 3 is expected on unsupported hosts. See `docs/STAGE_63_INDEPENDENT_LINUX_LAB_MAC.md`.
