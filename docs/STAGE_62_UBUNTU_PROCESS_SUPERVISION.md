# Stage 62 — Ubuntu Server Process Supervision & Verified Recovery

## Scope

Opt-in `CYBERSEC_PROCESS_SUPERVISION=1` enables POSIX process-group isolation for Nuclei and sqlmap CLI adapters. The supervisor uses `Popen(start_new_session=True)`, bounded `communicate`, SIGTERM then SIGKILL to the process group on timeout/cancellation, and always reaps the direct child. No external scanners are executed by the local tests.

## Limitations / NO-GO

* Process groups are not a security boundary. Double-fork, setsid, process reparenting, privilege changes and worker SIGKILL can escape in-process supervision. An independent systemd service manager with cgroup v2 delegation and `KillMode=control-group` is required for production-grade descendant containment.
* Worker-level cancellation is not yet wired into the adapter cancellation callback; the supervisor supports cancellation but the current adapters only enforce timeout. Therefore end-to-end cancellation and crash recovery remain **BLOCKED / NO-GO**.
* `CYBERSEC_PROCESS_SUPERVISION=1` is opt-in to retain compatibility with existing tests and legacy execution paths. Production admission must reject the legacy path before deployment.
* Existing database context manager `cybersec.db.connect` explicitly closes connections. SQLite test fixtures using `with sqlite3.connect` may require explicit `close()` because sqlite3's context manager only commits/rolls back.
* Expired external leases remain failed with manual recovery required; do not automatically retry external tools.

## Ubuntu Server integration plan (NOT EXECUTED)

1. Use dedicated unprivileged scanner service account and systemd `KillMode=control-group`, `Delegate=` only when required, cgroup v2.
2. Confirm authorized isolated lab targets and pinned tool versions.
3. Run subprocess-only fixtures to test SIGTERM/SIGKILL, descendants, concurrent starts, timeout, cancellation and worker SIGKILL.
4. Verify systemd restarts, orphan-free process trees, PID reuse, lease fencing, and operator-authenticated manual recovery.
5. Only then run authorized ZAP/Nuclei/sqlmap integration tests and record PASS/FAIL evidence.


> **Stage 63 supersession:** The Stage 62 limitation about worker cancellation not being wired is historical. Stage 63 integrates cooperative worker cancellation for POSIX supervised subprocess adapters. The independent systemd/cgroup containment, SIGKILL-of-worker and process escape limitations remain **NO-GO**. See `STAGE_63_STRICT_REGRESSION_AND_CANCELLATION.md`.
