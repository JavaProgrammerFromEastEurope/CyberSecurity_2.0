# Requirements Traceability — Stage 54

**Baseline:** Stage 53 / 2.33.0  
**Documentation release:** Stage 54 / 2.34.0

This matrix separates implemented source functionality from partial coverage and from capabilities that are not demonstrated by the Stage 53 source tree. “Implemented” means a code path and related tests/docs exist in the archive; it does not mean production acceptance has been completed.

## Status definitions

- **Implemented** — corresponding code path is present in the source baseline.
- **Partial** — a limited implementation exists, but the broader product requirement is not met.
- **Missing** — no implementation was established in the reviewed source tree.
- **Not externally verified** — repository configuration or code exists, but external execution/deployment evidence is absent.

## Traceability matrix

| Requirement / capability | Status | Evidence in Stage 53 | Remaining work / acceptance condition |
|---|---|---|---|
| Register assessment targets and record authorization acknowledgement | Implemented | Target, scope and runner modules; target/runner/scope tests | Validate authorization workflow and auditability in a controlled customer-like process |
| Shared scanner adapter contract and registry | Implemented | `scanners.py`, `models.py`, runner tests | Define adapter compatibility/version policy |
| Offline demo scanner | Implemented | Demo adapter and runner tests | Keep explicitly labeled as demo; never present as real scan evidence |
| OWASP ZAP integration | Partial | Passive-only adapter and tests | Add separately gated profiles only after authorization model and scope controls are explicit |
| Nuclei integration | Implemented | Constrained subprocess adapter and tests | Validate pinned binary/template versions and operational behavior in an authorized lab |
| sqlmap confirmation | Missing | No executable adapter established in default registry | Implement bounded, finding-driven confirmation with strict scope and safe defaults |
| Durable asynchronous scanner jobs | Missing | Job runner executes synchronously; API queued metadata is not execution | Dedicated durable scan queue, worker leases, retries, cancellation and crash recovery |
| Notification delivery queue/worker | Implemented | Delivery queue, notification worker, retry/quarantine tests | Keep separate from scanner-job execution |
| SQLite persistence | Implemented | `db.py`, repository and repository tests | Document backup, migration and concurrency limits |
| PostgreSQL / Redis production backend | Missing | No configured backend established | Add only if validated concurrency/scale requirements justify them |
| Finding normalization and first-pass deduplication | Partial | Fingerprint-based identity and merge behavior; repository tests | Stable taxonomy and explainable cross-tool semantic correlation |
| Raw scanner artifact retention and provenance | Implemented | `artifacts.py`, provenance fields and artifact tests | Define retention, access control, encryption and customer export policy |
| Risk scoring and analytics | Implemented | Risk/analytics/contextual-risk modules and tests | Validate scoring calibration with representative authorized findings |
| Remediation tracking and SLA workflow | Implemented | Repository/API/dashboard workflows and stage tests | Customer workflow acceptance, permissions and operational metrics |
| Risk intelligence and policy governance | Implemented | Risk rules, versioning, approval, exceptions and evidence modules/tests | Validate governance model with real operator roles and audit requirements |
| HTML technical and executive reports | Implemented | `reports.py`, report tests and README | Validate report completeness and customer acceptance |
| PDF reports | Missing | No PDF generation pipeline established | Add accessible, reproducible PDF output and content-equivalence tests |
| API and local dashboard | Partial | API, typed client, dashboard and hardening tests | Clarify identity, roles, session lifecycle, tenant isolation and deployment boundary |
| Full multi-user identity / RBAC / tenant isolation | Missing | Not established by current source baseline | Threat model and explicit authorization model before exposing beyond trusted local use |
| Portable evidence bundles and cryptographic verification | Implemented | Evidence bundle, custody, Ed25519, trust registry and offline verification modules/tests | Operational key custody, rotation, trust-anchor distribution and independent retention |
| Stage 53 revalidation history | Implemented | `revalidation_history.py`, CLI and Stage 53 tests/docs | Add process-safe concurrent append protection and external checkpoint strategy |
| Docker application image / Compose files | Partial | `Dockerfile`, `compose.yaml` | Verify complete scanner-enabled topology, secrets, volumes, health checks and isolation |
| CI workflow definition | Implemented | `.github/workflows/ci.yml` | External CI run status is not externally verified in this archive |
| Python 3.11/3.12/3.13 CI execution | Not externally verified | Workflow declares a version matrix | Capture successful CI run artifacts/logs for each supported version |
| Authorized end-to-end scanner validation | Not externally verified | Unit tests and adapter code only | Run against a disposable, explicitly authorized lab and retain bounded evidence |
| Customer-ready release acceptance | Missing | No acceptance evidence in archive | Complete P0/P1 work, deployment/security review and customer acceptance checklist |

## Product acceptance gates

A release must not be called customer-ready until all of the following are evidenced:

1. Scanner jobs execute asynchronously with durable state, safe retries, cancellation and crash recovery.
2. Every active scanner action is explicitly authorized and constrained to registered target scope.
3. Scanner outputs retain source evidence and have explainable normalization/correlation.
4. Reports expose scope, methodology, limitations, severity rationale, evidence and remediation guidance.
5. Identity, access control, tenant boundaries and secrets handling are explicitly threat-modeled and tested for the intended deployment.
6. A scanner-enabled isolated deployment passes build, startup, health, recovery and authorized lab tests.
7. CI and supported Python-version results are available as run evidence.
8. Documentation, release artifacts and rollback/backup procedures are complete.

## Priority

- **P0 — execution correctness and safety:** durable scanner queue/workers; bounded sqlmap confirmation; explicit ZAP scan profiles/authorization gates; explainable cross-tool correlation.
- **P1 — customer deliverables and access model:** PDF report; portable client package; identity/RBAC/tenant model.
- **P2 — deployment and scale:** scanner isolation/Compose topology; database concurrency/scale assessment; gated lab and performance suites.


## Stage 55 update

| Requirement | Stage 55 status | Notes |
|---|---|---|
| Durable scanner job queue/claim | Partial → Implemented for SQLite claims | Atomic `BEGIN IMMEDIATE` claim and unique active lease ownership are implemented. |
| Dedicated scanner worker | Implemented | `cybersec scanner-worker` is separate from notification workers. |
| Lease renewal and stale recovery | Implemented | Heartbeat renews leases; expired jobs are reclaimable. |
| Bounded retry attempts | Implemented | Attempt count and configured maximum are persisted. |
| Running-job cancellation | Partial | Cancellation request is persisted; universal immediate process interruption is not supported by the synchronous adapter contract. |
| Exactly-once scanner execution | Missing / not guaranteed | A crash after external scanner side effects can cause a retry. |


## Stage 63 update

| Requirement | Stage 63 status | Remaining gap |
|---|---|---|
| Worker cancellation propagates into subprocess | Implemented for local POSIX supervised child-process adapters | ZAP HTTP calls and untrusted/custom adapters need separate cooperative controls |
| SIGTERM/SIGKILL cleanup on timeout and cancellation | Implemented for POSIX process groups, fixture-tested | Not a cgroup/systemd process-tree guarantee |
| SQLite `ResourceWarning` / `DeprecationWarning` closure | Full strict Python regression performed; explicit SQLite connection-close regression tests added | Prior host's timeout not reproduced, no unsupported root cause claimed |
| External job fail-closed recovery | Expired lease and interrupted external work cannot automatically retry | External process stop and operator identity not independently verified |
| Ubuntu Server and production readiness | BLOCKED / NO-GO | Gated Ubuntu integration, OS-MAC confinement, service manager, cross-UID and authorized scanner lab tests |
