# Stage 64 — Ubuntu Server 26.10 compatibility, lifecycle and fail-closed admission

**Version:** 2.44.0 · **Decision:** BLOCKED/NO-GO · **Host acceptance:** NOT PERFORMED.

## Provenance and branch reconciliation

Input ZIP: `cyber_securuty_2.0_stage_63.zip`, SHA-256
`a1146e669d7b9b69cb6c19bae1d8d90fddb17ed6576a76b340363745a73c262e`.
Source branch `chat-stage63-v2.43.0`: head
`c9403ab5951763368c4423ba8ef6ef222a7ed6f3`, 125 tracked files.
Alternative branch `prework_cybersecurity`: head
`0745ebd08e6f56c1d35dbb08463c4d8631b230af`, 131 tracked files.
The Git trees have **13 conflicting paths** (different blob SHAs), **13
chat-only** and **19 prework-only** paths. The two projects independently
allocated Stage 61–63; do not merge wholesale and do not treat a shared
version number as functional equivalence.

The chat line contains `pdf_reports.py`, `process_supervisor.py` and worker
cancellation. The prework line contains `cgroup_containment.py`,
`stage63_host.py`, `recovery_authority.py`, signature-bound lab tickets and
policy requirements, but not the same PDF API. Shared changed files include
`cli.py`, `runner.py`, `scanners.py`, `repository.py` and `pyproject.toml`.
Those modules cannot be transplanted without porting their associated schema,
imports, process contracts and tests. Stage 64 uses the chat ZIP as cumulative
source of truth, documents the prework requirements, and implements a separate
read-only compatibility probe and conservative production runtime denial.
Neither original branch, tag nor ZIP is changed.

## Requirement and architecture map

| Source / TЗ goal | Stage 64 implementation | Contract & acceptance |
|---|---|---|
| Controller vs worker vs aggregator separation | Existing CLI/API, scanner-worker and reporting remain intact | No synchronous API scanner dispatch introduced |
| Controlled execution | `production_admission.py` / `stage64_runtime.py` | Any production-mode runner, worker and built-in scanner adapter rejects; legacy same-UID bypass still unproven at OS layer |
| systemd lifecycle | `deployment/stage64/cybersec-scanner-worker.service.candidate` | Independent PID 1 manager; `KillMode=control-group`, `SendSIGKILL`, `Restart=no`, fail-closed `ExecStartPre` |
| Ubuntu 26.10 | `host-preflight`, `stage64_runtime.audit_host` | Check Ubuntu 26.10, Python 3.14, OpenSSL 4, systemd >=261, cgroup v2, AppArmor, UID separation |
| PID/cgroup identity | `process_identity.py` | Stable PID start ticks with cgroup observations; no PID-signal authority or scanner admission |
| PDF/HTML and traceable evidence | Previous Stage 61–63 source/API unchanged | Legacy report tests must continue to pass |
| ZAP/Nuclei/sqlmap integration | No executable changes to scanning options | External scanners never run in Stage 64 development tests |
| Customer release | Additional Ubuntu opt-in integration fixtures | NO-GO until real host and independent MAC/cgroup/recovery evidence |

## Protocol & invariants

1. A *read-only inventory* must not write kernel controls, create root-owned
   approval files, load AppArmor profiles, or grant execution authority.
2. `host-preflight` and `python -m cybersec.stage64_runtime` always return **3**
   with JSON status **BLOCKED/NO-GO**. The output includes each failed check.
3. A process in `CYBERSEC_EXECUTION_MODE=production` or
   `CYBERSEC_RUNTIME_MODE=production` refuses `JobRunner.run`,
   `run_scan_worker`, and direct built-in ZAP/Nuclei/sqlmap adapters. This is
   defense in depth, not independent OS-enforced production confinement.
4. The candidate systemd unit requires independently provisioned identity and
   AppArmor policy, refuses to start via `ExecStartPre`, and intentionally has
   `Restart=no` to avoid a restart loop before admission is implemented.
5. Development/demo scanning, HTML/PDF and offline cryptographic verification
   remain available without privileged or network scanner actions.
6. `ProcessIdentity(pid,start_ticks,cgroup)` detects PID reuse between
   observations, but cannot atomically guarantee process authority or kill
   descendants. This will require pidfd/cgroup v2 and independent OS-MAC tests.

## Safety analysis / residual failure modes

- **Environment-variable bypass:** an unconfined same-UID legacy process can
  unset the production mode; the OS must deny that path independently.
- **Double fork/setsid:** POSIX process-group signalling is insufficient when
  a child migrates out of the group; systemd ownership and cgroup boundaries
  require real host validation. There is no general orphan guarantee here.
- **PID reuse:** startticks/cgroup observation is useful diagnostics, not a
  substitute for pidfd/process identity and independently authenticated proofs.
- **Privilege separation:** four different service users, protected binaries,
  key ownership, audited AppArmor denial of `cgroup.procs` writes are absent
  in the current Debian environment and cannot be inferred from a file.
- **Host toolchain:** Ubuntu 26.10 Python 3.14/OpenSSL 4 and ReportLab or
  cryptography dependencies are not executed in the Debian 13 environment.
- **Permit/replay:** no independent signed one-use per-attempt authority or
  hardware-backed durable anti-rollback root in this chat codebase. NO-GO.

## Testing and evidence policy

The `tests/test_stage64_ubuntu_runtime.py` file uses Python-only process
fixtures. `tests/integration/test_stage64_ubuntu.py` requires explicit opt-in
and an actual Ubuntu 26.10 host. The strict suite treats ResourceWarning and
DeprecationWarning as errors; all completed and failed runs, stdout/stderr,
return codes and hashes are collected in `evidence/stage64/`. A successful
unit test does not establish OS admission. Scanner executables are not invoked.

## Version and compatibility policy

Stage 64 remains cumulative and does not add migrations or change the
existing CLI/API/DB models or PDF report signatures. It adds a new offline
`cybersec host-preflight` command, the new host inventory and diagnostic
process identity API. Both historical Stage 63 trees remain separate.

### One-shot approval ordering (Stage 64 corrective check)

`sqlmap_gate.execute_approved_confirmation` now checks mandatory production
admission **before** calling `claim_sqlmap_confirmation`. A blocked production
request must not consume a repository-backed one-shot confirmation permit.
The direct sqlmap adapter independently performs the same admission check
before argument validation or any executable lookup/launch.
