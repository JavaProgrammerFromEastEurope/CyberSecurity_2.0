# Stage 55 — Durable Scanner Job Execution Foundation

**Release:** 2.35.0

## Delivered

- Durable SQLite claim/lease metadata on scan jobs: owner, expiry, attempt count, retry limit and cancellation request timestamp.
- Atomic worker claim using `BEGIN IMMEDIATE`; an active lease cannot be claimed by a second worker.
- Expired leases can be reclaimed; jobs that exhaust the configured attempt limit become failed.
- Lease renewal heartbeat runs independently while a synchronous adapter is executing.
- A dedicated `scanner-worker` CLI process is separate from notification delivery workers.
- Claimed-job completion is restricted to the current lease owner.
- Queued jobs can be cancelled; running jobs receive a persisted cancellation request.

## Run

```bash
cybersec scanner-worker --worker-id scanner-01
cybersec scanner-worker --worker-id scanner-02 --lease-seconds 90 --idle-seconds 1
cybersec scanner-worker --worker-id one-shot --max-jobs 1
```

Create a job as before:

```bash
cybersec job create https://your-authorized-lab.example --tool demo
```

The API remains metadata-only. It does not start scanners. Dedicated worker processes poll the same configured database.

## State and recovery

A worker atomically claims a queued job, increments `attempt_count`, records its owner and lease expiry, and transitions it to `running`. The heartbeat extends the lease. If a process disappears, another worker may reclaim the job after lease expiry. Repeated lease expiry is bounded by `--max-attempts`.

## Cancellation limitation

Queued jobs are cancelled immediately. For running jobs, cancellation is recorded as a request and prevents lease renewal. The current adapter contract is synchronous and does not yet provide a universal interrupt/cancellation token; therefore an already-running external scanner may continue until its own timeout or completion. Stage 55 does not claim hard process termination. Adapter-level cooperative cancellation is a follow-up hardening item.

## Operational constraints

- SQLite is the supported persistence backend for this stage.
- Use a shared database file on a local filesystem for multiple workers; do not assume network-filesystem locking semantics.
- Configure lease duration above expected heartbeat delays. The worker renews at roughly one-third of the lease duration.
- A crash after a scanner side effect but before result persistence can cause a retry. Scanner operations must remain bounded and safe; exactly-once external execution is not guaranteed.
- The old `cybersec job run ID` synchronous command remains available for compatibility. Production background execution uses `scanner-worker`.
- Notification delivery workers remain independent and unchanged.
