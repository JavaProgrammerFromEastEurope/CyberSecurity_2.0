Stage 61: worker-owned Nuclei process supervision, cooperative cancellation, POSIX SIGTERM/SIGKILL escalation and fencing. See docs/STAGE_61_PROCESS_SUPERVISION.md.
Stage 60: conservative scanner execution recovery policy. See docs/STAGE_60_EXECUTION_RECOVERY.md.
Stage 59: atomic worker result commit with attempt fencing. See docs/STAGE_59_ATOMIC_RESULT_COMMIT.md.

# Cyber Security Orchestrator 2.0

**Current release: 2.41.0 — Stage 61**

An authorized security assessment orchestrator with evidence provenance, offline cryptographic verification, trust-registry snapshots, and continuous trust monitoring. The project retains earlier stages and their tests.

## Stage 55: Durable scanner job workers

Stage 55 adds a durable SQLite-backed scan-job claim/lease mechanism and a dedicated `cybersec scanner-worker` process. Multiple workers can claim distinct jobs atomically; expired leases are recoverable and retries are bounded. Running-job cancellation is recorded as a request; immediate interruption of a synchronous scanner process is not yet guaranteed. See `docs/STAGE_55_SCANNER_WORKERS.md`.

## Stage 54: Architecture and requirements baseline

Stage 54 is a documentation-only baseline. It updates the architecture description, maps product requirements to implemented/partial/missing/unverified status, and defines measurable integration gates for Stages 55–60. No runtime behavior is changed.

See `docs/ARCHITECTURE.md`, `docs/REQUIREMENTS_TRACEABILITY.md`, and `docs/INTEGRATION_PLAN.md`.

## Stage 53: Tamper-evident revalidation history

Create a hash-chained offline history from reports produced by `evidence revalidate`:

```bash
cybersec evidence history-append --report revalidation.json --history revalidation-history.jsonl
cybersec evidence history-verify --history revalidation-history.jsonl
cybersec evidence history-export --history revalidation-history.jsonl --output audit-package.json
cybersec evidence history-package-verify audit-package.json
```

The chain links each report digest to a predecessor and checks sequence order, allowing offline detection of modifications, deletions inside the chain, substitutions, and reordering. Export packages include the chain and a verification result. For robust truncation detection, preserve the history head hash or exported package independently. The format is tamper-evident, not author-authenticating; no private signing key is stored in history packages.

## Stage 52: Trust monitoring

### Compare signed registry snapshots

```bash
cybersec evidence trust-diff \
  --previous-snapshot reports/trust-before.json \
  --current-snapshot reports/trust-current.json \
  --registry-public-key ./trusted-registry-signer.pub \
  --output reports/trust-diff.json
```

Both snapshots must validate against the explicitly supplied Ed25519 public key. The report identifies key additions/removals, key-material or registration-time changes, revocation transitions, and whether the previous snapshot's audit events are still present in the current snapshot.

### Revalidate evidence bundles

```bash
cybersec evidence revalidate \
  --evidence-dir reports/evidence \
  --trust-snapshot reports/trust-current.json \
  --registry-public-key ./trusted-registry-signer.pub \
  --previous-report reports/revalidation-previous.json \
  --output reports/revalidation-current.json
```

The command checks top-level `*.json` files that use the portable evidence-bundle format and records status transitions. Exit code is `0` only when all processed bundles are valid; invalid trust snapshot or invalid bundles return a non-zero status. Non-bundle JSON files are skipped.

## Trust and security model

- Registry snapshots and signed evidence are verified with Ed25519 and SHA-256 canonical JSON.
- Trust anchors are supplied independently; a snapshot cannot make its own signer trusted.
- Private keys are supplied at runtime and are not included in reports.
- Offline operations do not initialize or connect to the application database.
- A valid signature establishes cryptographic provenance, not the truth of the evidence.
- Comparisons only describe the signed snapshots provided. They cannot prove that an operator recorded every real-world event, and an old snapshot cannot show later revocations.
- Previous revalidation reports are comparison inputs, not authenticated historical records unless separately protected by an external process.

## Development checks

Run tests from the project root with the package installed or with `PYTHONPATH=src` configured:

```bash
PYTHONPATH=src python -m pytest
PYTHONPATH=src python -m cybersec --help
PYTHONPATH=src python -m cybersec evidence revalidate --help
PYTHONPATH=src python -m cybersec evidence trust-diff --help
```


## Release validation boundary

Automated tests and CLI smoke checks do not by themselves establish production readiness. Scanner-enabled deployment, external CI results, supported-runtime verification, and authorized end-to-end lab evidence must be recorded separately before claiming customer readiness.

Stage 57: repository-backed one-shot SQLmap candidate approval (`docs/STAGE_57_SQLMAP_APPROVAL.md`).
