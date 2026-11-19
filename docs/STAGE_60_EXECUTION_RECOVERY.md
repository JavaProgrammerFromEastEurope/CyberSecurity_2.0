# Stage 60 — Scanner Execution Idempotency & Recovery Policy

- Expired external scanner leases (`zap`, `nuclei`, `sqlmap`) are terminally marked `failed` rather than automatically reclaimed. This avoids *automatic* duplicate launches when a lost worker's subprocess might still run.
- The offline `demo` adapter retains bounded automatic retries and fencing-token protections.
- Generic scanner workers do not claim `sqlmap` jobs: its finding-linked approval path is not integrated into the generic queue.
- Operators may request a **new** `zap` or `nuclei` job only after explicitly confirming the prior external process has stopped. `Repository.request_manual_scan_recovery` records old/new job IDs and the operator-supplied identity in `scan_recovery_audit`.
- Operator identity is **not authenticated** by this method. Process termination is an operator assertion, not independently verified. No guarantee of exactly-once external execution or distributed cancellation is made.
- Stage 60 adds SQLite multi-worker claim tests; true multi-process and external-scanner crash tests remain future work.
