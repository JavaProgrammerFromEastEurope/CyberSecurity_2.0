# Stage 63 — Strict Regression Closure & Worker Cancellation Integration

Version: **2.43.0**. Source baseline: cumulative Stage 62 / 2.42.0. No real scanners were started while implementing or testing this stage.

## Runtime changes

1. The `scanner-worker` CLI installs temporary SIGTERM/SIGINT handlers. Both signal handlers set an in-memory stop event; they are removed after the worker exits. SIGKILL cannot be caught.
2. The claimed `JobRunner` passes an internal, in-memory `_worker_interrupted` callback to adapters. This is **not** a user-configurable scanner option. The callback checks the stop event, heartbeat lease loss, persisted cancellation, lease owner, expiration and fencing attempt number in SQLite. Database-read failures propagate; the supervisor then kills the process group before propagating the exception.
3. A worker-owned **Nuclei** adapter run always takes the POSIX `ProcessSupervisor` path even if `CYBERSEC_PROCESS_SUPERVISION` is unset. Thus a non-POSIX worker fails closed rather than silently falling back to un-supervised execution. The sqlmap adapter additionally accepts the callback when invoked explicitly, but **sqlmap remains outside the default worker registry**; Stage 57 finding-linked admission is not replaced.
4. `ProcessSupervisor` attempts SIGTERM and bounded draining, then SIGKILL against the process group; repeated pipe draining is also bounded. If a descendant escapes the group and retains pipes, the supervisor reports incomplete containment rather than hanging indefinitely. The direct child is reaped where the operating system permits it.
5. After an interrupted non-cancelled external job (e.g. cooperative worker shutdown), the job is marked failed with `manual recovery required`. Cancelled jobs become `cancelled`. A stale lease cannot commit result artifacts and later recovery still requires an explicit operator acknowledgement.
6. Existing direct-CLI adapter calls remain compatible with Stage 62's optional `CYBERSEC_PROCESS_SUPERVISION=1`. **This legacy opt-out is not production-safe**; admission-fencing is a future requirement. ZAP's local HTTP API is not a child process of `ProcessSupervisor` and is not immediately interrupted by this mechanism. A `ScanContext` consumer implemented outside the built-in Nuclei adapter must explicitly honor the cooperative callback.

## Regression and warning diagnostics

The archived Stage 62 evidence explicitly reports `strict_full_pytest` exit code **124**, `timeout: true` and elapsed **15.007 seconds** (`evidence/stage62/results.json`). The current complete Stage 62 baseline took **46.67 seconds** for 287/287 tests, and subsequent Stage 63 strict suites took approximately 46–49 seconds. Thus the prior **15-second execution bound was insufficient**; no assertion of an underlying pytest deadlock is supported. The Stage 63 full-suite command has an explicit **180-second** wall-clock bound, and the final run completed within it.

The Stage 62 baseline and all Stage 63 full regressions use `-W error::ResourceWarning -W error::DeprecationWarning`. None surfaced either warning category in this environment. `cybersec.db.connect()` already explicitly closes SQLite handles on success and exception; Stage 63 adds regression tests proving that lifecycle. Stage 62 had corrected a legacy test's raw `sqlite3.connect` lifecycle. Claiming an additional unobserved warning fix would be inaccurate.

Original failing SIGTERM/SIGKILL tests and their logs are retained: the Python test fixture initially received a signal before its runtime was ready. Tests were changed to wait for an explicit ready marker. The corrected tests pass; this was a **test fixture race**, not evidence that the target scanner process supervisor failed.

### Tests

- Strict full suite: `PYTHONPATH=src python -W error::ResourceWarning -W error::DeprecationWarning -m pytest -vv --tb=short`
- Stage 63 tests: `PYTHONPATH=src python -W error::ResourceWarning -W error::DeprecationWarning -m pytest -q tests/test_stage63_worker_cancellation.py tests/test_stage63_sqlite_lifecycle.py`
- The two Ubuntu integration tests under `tests/integration/` are skipped by default and **never** start ZAP, Nuclei or sqlmap.
- Logs, exit codes, sha256 manifest, and PASS/FAIL history: `evidence/stage63/`.

## Ubuntu Server integration — NOT PERFORMED HERE

The source includes `tests/integration/test_stage63_ubuntu.py`, which is expressly gated by the `CYBERSEC_UBUNTU_SERVER_TESTS=1` environment variable and Linux OS. It uses sleeping, local Python fixtures only. Suggested execution on an isolated Ubuntu Server:

```bash
python3 -m venv .venv
.venv/bin/pip install -e '.[dev]'
CYBERSEC_UBUNTU_SERVER_TESTS=1 PYTHONPATH=src \
  .venv/bin/python -W error::ResourceWarning -W error::DeprecationWarning \
  -m pytest -vv tests/integration/test_stage63_ubuntu.py
```

Additional required manual evidence, beyond these tests:

- Independently managed, non-root systemd service, `KillMode=control-group`, verified cgroup v2 scope and delegation, OS-enforced confinement, service-manager restart and worker SIGKILL.
- Cross-UID enforcement and independent recovery authority; PID reuse, concurrent starts, double-fork/setsid escape attempts, SIGKILL at SQLite commit and IPC boundaries, surviving process detection, socket and file replacement, and rollback/replay checks.
- The operator's `external_process_stopped` acknowledgement is currently a **caller-supplied boolean**, not externally attested process termination or authenticated operator identity.
- Complete external tool/lab acceptance with explicit authorization and production RBAC/tenant controls.

**Deployment assessment: BLOCKED / NO-GO**. Passing Python regression tests cannot prove systemd/cgroup containment or safe production operation. The example unit in `docs/ubuntu/` is a proposed reference configuration, not an installed or independently validated service.
