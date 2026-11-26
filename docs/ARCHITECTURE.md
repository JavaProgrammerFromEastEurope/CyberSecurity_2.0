# Cyber Security 2.0 — Architecture Baseline

**Baseline:** Stage 55  
**Release:** 2.35.0  
**Scope:** documentation-only baseline based on the Stage 53 source tree. No scanner behavior, database schema, API behavior, or runtime code is changed in this stage.

## 1. Product boundary

Cyber Security 2.0 is an authorized security-assessment orchestrator. It registers targets with an authorization acknowledgement, coordinates assessment records, invokes configured scanner adapters, retains findings and raw artifacts, supports risk/remediation workflows, and produces reports and portable evidence.

The application is not itself a general-purpose vulnerability scanner. Scanner capability is determined by the adapters actually registered and by the deployment configuration. A CLI option or a tool name in stored metadata does not prove that an executable adapter exists.

## 2. Runtime components

| Component | Responsibility | Baseline behavior |
|---|---|---|
| CLI (`cybersec.cli`, `__main__`) | Local commands for targets, jobs, findings, reports, evidence, workers and remote API operations | Command dispatch and validation; scanner execution depends on the selected path and registered adapter |
| Configuration (`config.py`) | Environment-based settings and runtime configuration | Local configuration; deployment-specific secrets must be supplied outside reports and archives |
| SQLite database (`db.py`) | Persistent application records | SQLite is the implemented persistence backend in this baseline |
| Repository (`repository.py`) | Data access and persistence operations | Stores targets, jobs, findings, remediation/governance records and related history |
| Scope (`scope.py`) | Target/origin scope checks | Used to constrain scanner and result handling to authorized target scope |
| Job runner (`runner.py`) | Coordinates scan lifecycle and adapter invocation | Retains synchronous compatibility mode; Stage 55 adds a dedicated worker path with SQLite atomic claims, leases, heartbeats and bounded retries |
| Scanner contract (`scanners.py`, `models.py`) | Scan context/result and adapter implementations/registry | Shared adapter contract; Demo, passive ZAP and constrained Nuclei paths are present |
| Scanner worker (`scan_worker.py`) | Claims and executes durable scan jobs | Separate process, SQLite lease ownership, heartbeat, bounded retries and stale-lease recovery; running cancellation is request-only for synchronous adapters |
| Notification delivery (`delivery_queue.py`, `worker.py`, `notifications.py`) | Notification leases, retries and delivery | Separate from scanner execution; notification and scanner worker queues are independent |
| API and client (`api.py`, `api_client.py`, `api_client_cli.py`) | Local HTTP API, typed client and remote CLI | Protected local-oriented API; do not infer full multi-user identity, role hierarchy or tenant isolation |
| Dashboard (`dashboard.py`) | Browser-based operational view | Local dashboard with authenticated/protected routes as implemented |
| Reporting (`reports.py`, `analytics.py`, `risk_analytics.py`) | HTML reports, metrics and risk explanations | Technical and executive HTML profiles; a supported PDF report generator is not established by this baseline |
| Artifact/evidence (`artifacts.py`, `evidence_audit.py`, `evidence_offline.py`) | Raw artifact retention, portable evidence, signatures and custody | Hashes, optional HMAC, Ed25519 signing/trust workflows, offline verification |
| Trust/revalidation (`trust_registry.py`, `trust_monitor.py`, `revalidation_history.py`) | Signed trust snapshots, comparison and revalidation history | Offline trust snapshot comparison, evidence revalidation and hash-chained JSONL report history |

## 3. Scanner execution and safety boundary

### Demo adapter
The demo adapter is an offline/test path. It does not establish that a real target has been assessed.

### OWASP ZAP
The implemented ZAP adapter is passive-only. It communicates with a loopback ZAP API, requests the registered target URL without following redirects, waits for passive scanning, and filters returned alert URLs to the registered target origin. It does not invoke Spider, Ajax Spider or Active Scan endpoints.

### Nuclei
The Nuclei adapter launches a constrained subprocess using a fixed argument list and `shell=False`. The implementation applies bounded timeout/rate/concurrency settings, fixed conservative tags, parses JSONL output, and drops results outside the registered target origin. Matches remain tentative until subsequent validation/normalization.

### sqlmap
A runnable sqlmap adapter and a bounded finding-confirmation workflow are not part of the default registered scanner implementation in this baseline. Stored tool labels or roadmap references are not executable integration.

### Scan jobs versus notification workers
The scan runner is synchronous in the invoking process. API job creation records queued job metadata; it does not by itself start scanner execution. The lease/retry worker infrastructure belongs to notification delivery and is not a scan-job queue.

## 4. Data and finding lifecycle

1. A target is registered with an authorization acknowledgement.
2. A job record is created and validated against target/job state.
3. The runner resolves a registered adapter and passes a scan context.
4. Adapter results are normalized into finding records; a first-pass SHA-256 fingerprint supports deduplication.
5. Scanner payloads can be retained as artifacts with source metadata and content hashes.
6. Findings feed risk scoring, comparison, remediation, SLA and risk-intelligence workflows.
7. Reports and portable evidence outputs are generated from retained records.

The fingerprint is a pragmatic identity key based on target, normalized URL, parameter and normalized vulnerability type. It is not universal semantic correlation across scanners. Evidence and source provenance should remain attached when records are merged.

## 5. Risk, remediation and governance

The repository contains risk scoring/analytics, target criticality, remediation tasks, SLA states and verification evidence, trend metrics, risk-intelligence alerts, versioned risk rules, approval/exception workflows and policy evaluation evidence. These features support analyst workflow and governance; they do not independently prove that a vulnerability is exploitable or that remediation is effective without a retest.

## 6. Reporting and evidence

- HTML reporting supports technical and executive profiles.
- JSON/CSV exports and integrity manifests exist in relevant workflows.
- Evidence bundles support integrity checks and optional authentication/signatures.
- Ed25519 trust and key lifecycle workflows include signed custody checkpoints and signed trust-registry snapshots.
- Stage 53 adds an offline JSONL hash chain for revalidation reports and portable audit-package verification.

Cryptographic integrity/provenance does not prove the factual truth of scanner evidence. A hash chain without an independently preserved checkpoint cannot prove that its final tail was not truncated. A signature is only as trustworthy as the separately managed trust anchor and key lifecycle.

## 7. Persistence and deployment

SQLite is the established database backend. PostgreSQL and Redis are not established as configured production backends in this baseline. The repository contains a Dockerfile and Compose configuration, but the presence of those files does not establish a production scanner deployment with dedicated scan workers or isolated scanner services.

The CI workflow declares Python-version test jobs and static/test commands. Configuration in a workflow file is not evidence that an external CI run has passed; CI run results must be checked in the hosting platform.

## 8. Known architectural gaps

1. Running scanner cancellation is persisted as a request but does not yet guarantee immediate process interruption; exactly-once external execution is not guaranteed.
2. No bounded sqlmap confirmation adapter/workflow.
3. No configurable, explicitly authorized ZAP Spider/Ajax Spider/Active Scan profiles.
4. No robust cross-tool semantic correlation beyond first-pass finding identity/deduplication.
5. No demonstrated PDF reporting pipeline.
6. Full user identity, role model and tenant isolation are not established.
7. No verified scanner-enabled production Compose deployment or authorized end-to-end lab evidence.
8. Process-level locking for concurrent JSONL history appenders is not established by the Stage 53 design.
9. External CI success and multi-version runtime test results are not included in this source archive.

## 9. Baseline validation policy

A release claim must distinguish:
- source/configuration presence;
- local automated test results;
- CLI smoke-test results;
- container build and runtime results;
- authorized end-to-end scanner results;
- external CI results.

Passing unit tests does not imply scanner integration, production readiness, authorization correctness in a real deployment, or customer acceptance.


## Stage 55 execution model

The scan-job queue is persisted in SQLite. Workers claim jobs under `BEGIN IMMEDIATE`, with one active lease owner per job. A heartbeat renews the lease while a synchronous adapter runs. Expired leases are recoverable and attempts are bounded. This is a single-database SQLite worker model, not a distributed broker. The legacy synchronous `job run` path remains for compatibility; the dedicated `scanner-worker` command is the background execution path.
