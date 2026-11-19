# Stage 61 — Worker Process Supervision & Safe Cancellation (v2.41.0)

**Scope:** This stage implements local POSIX process supervision for **worker-owned, conservative Nuclei invocations**, checks ZAP cooperative cancellation, and closes the same-worker-id stale-attempt completion path. It does **not** enable SQLmap in the generic queue or ZAP active scanning.

## Requirements and result contracts

| ID | Requirement | Implementation and evidence | Guarantee |
| --- | --- | --- | --- |
| PS-01 | Stop locally spawned scanner on a cancellation request | SQLite cancellation flag -> 200 ms lease observer -> abort event -> supervised process group | Verified with an offline local Python executable, not live Nuclei |
| PS-02 | Bound runtime and output | Monotonic deadline, bounded in-memory stdout/stderr, drain while running | Verified with actual subprocesses |
| PS-03 | TERM/KILL escalation | `start_new_session=True`, `killpg(SIGTERM)`, bounded grace, `killpg(SIGKILL)` | Verified for subprocess ignoring TERM; *not* OS-enforced descendant confinement |
| PS-04 | Abort on lost lease or shutdown | Observer checks status, attempt and owner; CLI handles SIGTERM/SIGINT; worker observes shutdown | Verified in unit/integration fixtures; no host service-manager E2E proof |
| PS-05 | No stale completion with recycled worker ID | `finish_claimed_scan_job(..., attempt=N)` requires matching token, `commit_claimed_scan_result` already fences | Verified with lease expiry/reclaim fixture |
| PS-06 | Avoid automatic duplicate scanner side effects | Stage 60 external lease expiry remains failed/manual-only | Verified by retained Stage 60 tests |
| PS-07 | ZAP cancellation | Check token before network actions and on each polling iteration | Local poll stops, shared ZAP daemon execution **not terminated** |
| PS-08 | Compatibility | Existing APIs retained; `JobRunner.run` and `finish_claimed_scan_job` gain optional kwargs | Previous tests retained; full regression evidence |

## Architecture

`scanner-worker` claims a SQLite lease (Stage 55/58), then `JobRunner` verifies authorization and lease. An observer thread examines status, `attempt_count`, `lease_owner`, expiry, and `cancel_requested_at` every ~200 ms and renews the lease separately. Observer failures are fail-closed for the running adapter; stale results cannot commit. The worker's Nuclei adapter uses `run_supervised` to launch a *fixed* argv array with no shell in a new POSIX session; stdout/stderr are drained nonblocking via selectors and bounded in memory. Signal handling in the CLI requests cooperative shutdown, including interruption of the active adapter.

The supervisor **never tries to kill a shared ZAP daemon**, nor assumes a cancellation request reverses external side effects. The unmodified synchronous legacy `job run` path retains its original adapter contract, including the historical `subprocess.run` path; **do not deploy it as a production scanner execution bypass**. Generic worker still will not claim SQLmap work.

## Crash, recovery, and restrictions

* A worker killed by SIGKILL has no opportunity to stop its child. The Stage 60 lease expiry policy prevents automatic rerun but cannot prove that a child stopped. An operator must verify external process termination before using the explicitly audited recovery method.
* `setsid`, double fork, process-group escape, host restart and PID reuse are **not covered by** `killpg` alone. Production execution requires independent OS-enforced delegated cgroup v2 or equivalent service-manager containment, service isolation, and tests under real UIDs. We do not claim that such mechanisms are installed or validated here.
* A SIGTERM delivered while a Python interpreter is not yet ready or a fatal host crash may leave uncertainty. Persistent effect records and independent authority must settle that uncertainty; do not infer success from SQLite state alone.
* ZAP passive mode is remote work inside the local ZAP daemon. `cancel_event` stops the coordinator's polling, **not** ZAP's remote processing. The original external-effects/manual recovery restrictions still apply.
* No real external scanning, exploitable test target, production customer credentials or automatic relaunch is introduced by Stage 61.

## Reproduction

```bash
python3 -m pip install -e '.[dev]'
PYTEST_DISABLE_PLUGIN_AUTOLOAD=1 PYTHONPATH=src \
  python -W error -m pytest -q tests/test_stage61_process_supervision.py
PYTEST_DISABLE_PLUGIN_AUTOLOAD=1 PYTHONPATH=src \
  python -W error -m pytest -q
```

`PYTEST_DISABLE_PLUGIN_AUTOLOAD=1` keeps unrelated system-installed pytest plugins (including plugin warning configurations) out of release qualification. The tests launch **only disposable local Python fixtures** and do not call real ZAP/Nuclei network endpoints. External integration and real OS containment are still **NO-GO** until evidenced.

## Subsequent gate

An independently authorized and isolated test lab must demonstrate real SIGTERM/SIGKILL, process-group and cgroup containment, worker crash/restart, ZAP cancellation bounds, multi-process SQLite fencing and no out-of-scope network traffic. Until then customer production acceptance is **BLOCKED/NO-GO**.
