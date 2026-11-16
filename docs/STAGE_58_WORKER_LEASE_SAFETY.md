# Stage 58 — Scanner Worker Cancellation & Lease Safety

Version: 2.38.0.

- Running cancellation is cooperative: the owner continues to renew its lease until the scanner returns.
- The owner finalizes a cancellation-requested job as `cancelled`, not `completed` or `failed`.
- If a cancelled worker disappears and its lease expires, the job becomes terminal `cancelled`; it is never reclaimed.
- Expired owners cannot renew or finish their jobs.
- A lease check fences stale workers before artifact publication.

**Limitations:** scanner subprocesses are not forcibly interrupted. The lease check and artifact write are separate database transactions, so an expiry between these operations can still allow a stale artifact write. A future stage should make artifact publication and job completion one atomic transaction with a per-claim fencing token, and provide adapter-level cancellation. This stage does not establish exactly-once external scanner execution.
