# Stage 59 — Atomic Scanner Result Commit & Fencing Tokens

Worker-owned scanner results are committed in a single SQLite `BEGIN IMMEDIATE` transaction: lease/attempt validation, artifact insertion and terminal job transition. `attempt_count` is the fencing token, so an expired worker cannot publish results even when its worker ID is reused. Cancellation prevents result artifact insertion.

The runner captures the attempt token before calling the adapter; stale commits raise and are rejected. The existing synchronous non-worker path remains unchanged.

Limitations: an external scanner can continue after lease expiry; this protects the database commit, not external side effects. Historical artifacts from previous successful commits remain retained.
