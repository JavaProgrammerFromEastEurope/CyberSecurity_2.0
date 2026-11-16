# Stage 56 — Bounded sqlmap confirmation adapter

The adapter `SqlmapConfirmationAdapter` is opt-in and deliberately excluded from the default scanner registry. Existing CLI and queued `sqlmap` jobs remain non-executable. This prevents starting an active confirmation without candidate provenance and a specific authorization gate. Direct Python callers must provide `ScanContext.options` with `authorized=True`, `candidate_recorded=True`, `candidate_url` and `parameter`. These booleans are caller attestations, **not independently verified repository records**. Do not expose this direct adapter to untrusted callers.

Candidate URL must be same scheme, hostname and port as the registered target, and within its URL path prefix. Parameter must occur in query string. The command uses a fixed minimal profile: `--risk=1 --level=1 --threads=1 --technique=BE`, timeout and no redirects. It does not support arbitrary flags, data extraction, or shell execution. Output is truncated and a digest is retained. Confirmation requires a recognizable GET parameter and boolean/error-based type in stdout; otherwise result is inconclusive. It is not a substitute for independent evidence validation.

## Remaining work

* Persist candidate-to-finding provenance and verify it against the repository, not caller flags.
* Integrate explicit approval workflow and scoped execution into job creation and worker dispatch.
* Add cancellation-safe subprocess process-group management and robust evidence redaction.
* Review scanner behavior against an isolated authorized lab before production use.
* Fix running-worker cancellation/lease-expiry race: a running process can outlive its lease after cancellation.
