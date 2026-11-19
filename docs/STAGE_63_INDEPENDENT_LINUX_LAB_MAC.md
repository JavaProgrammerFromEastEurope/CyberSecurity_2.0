# Stage 63 — Independent Linux Lab E2E & Mandatory MAC Confinement (v2.43.0)

## Scope and outcomes

This stage strengthens the **admission and observation boundary** inherited from
Stage 62, but the host running the build does not possess independently
administered Linux kernel/security facilities. **No independent Linux E2E,
production MAC or durable recovery authority has been established.**
The implementation is a fail-closed deployment candidate, not a completed
production admission. The currently installed environment has supervisor PID1,
read-only cgroup v2, no inspectable LSM stack and no four provisioned UIDs.

| Requirement | Implementation / evidence | Actual status |
| --- | --- | --- |
| C63-01: kernel-enforcing AppArmor/SELinux + role-specific service identity | `stage63_host.audit_host`, `/proc/PID/attr/current`, kernel securityfs and service property observations | Read-only negative evidence; no external MAC enforcement |
| C63-02: four independent nonroot users & service lifecycle | UID/GID role lookup, unit properties, `/proc/PID/status`, cgroup membership and PID starttime double checks | Not installed here |
| C63-03: deny same-UID legacy execution and cgroup escapes | `deployment/stage63/APPARMOR_POLICY_REQUIREMENTS.md`, mandatory OS negative tests | Not proven; blocks production |
| C63-04: SIGTERM/SIGKILL, PID reuse, setsid and double fork | Existing Stage 61/62 process/cgroup code, Stage 63 local process lifecycle test | Local process signals tested; cross-cgroup E2E blocked |
| C63-05: independently signed attempt-specific lab permit | Inherited `lab_authorization.verify_lab_ticket`; literal loopback-only target | Synthetic signature tests only; no real authorization |
| C63-06: independent monotonic recovery | Signed read-only `verify_recovery_receipt`, exact job/attempt/boot/checkpoint/monotonic-counter binding | **No** TPM2 root / external CAS; `require_independent_recovery_admission` always fails closed |
| C63-07: no bypass of production worker | Existing `scan_worker.run_scan_worker` refuses production without independently attested authority; existing legacy scanner gates | Library-only guard not OS enforcement; NO-GO |
| C63-08: full cumulative testing | `tests/test_stage63_independent_lab.py` plus previous stage suites | Per-regression evidence retained in archive |

## Architecture and safety contract

* Four proposed OS roles: worker, attester, witness and publisher. No two may
  share an effective or saved UID. MAC policy must forbid execution of any
  unconfined alternate worker/scanner from the worker's UID, as well as
  migrations through cgroup controls. A trusted independent authority must
  provision and verify installed policies, not merely inspect a policy filename.
* Worker-controlled cgroup v2 child is created before scanner exec; Stage 62
  process trampoline blocks until the parent proves membership and PID starttime.
  `pidfd` signals the leader, `cgroup.kill` kills all descendants including
  detached processes **if they have not escaped the cgroup**. Stage 63 has no
  acceptable evidence that MAC confinement prevents escape here.
* `stage63_host` observes process IDs twice, checks unique role separation and
  systemd control groups, and reports all blockers. It returns **exit 3**
  unconditionally and never grants production permission.
* `recovery_authority` verifies an Ed25519 artifact, canonical JSON, exact
  job/attempt identity, boot UUID, checkpoint SHA-256, bounded UTC lifetime and
  monotonic counter progression. The receipt is **manual-review-only**;
  a counter value inside signed JSON is not a durable monotonic witness.
  `require_independent_recovery_admission` validates root-pinned public keys
  and then rejects without independent secure one-use CAS. Never manufacture
  such a permit from a local file, test signing key or environment variable.
* Pre-existing ZAP remote daemon cannot be universally terminated. Do not
  treat cooperative cancellation as network side-effect rollback. Active ZAP,
  sqlmap, external Nuclei scanning and network tests are not authorized here.

## External acceptance tests required before any deployment

Under a physically/logically independent Linux lab controlled by the operator:

1. Review and enforce actual AppArmor/SELinux **worker and scanner** policies;
   prove denial of same-UID unconfined exec, alternate interpreter entrypoints,
   signing-key access and direct cgroup file writes by a scanner process.
2. Verify kernel LSM **denials** with audit records and independent witness;
   do not accept readable MAC labels as proof.
3. Run an approved loopback-only simulator (not live Nuclei) under a real
   delegated cgroup. Trigger setsid, double fork, PID reuse, SIGTERM, SIGKILL
   and demonstrate `cgroup.events populated=0` and no migration from cgroup.
4. Restart the systemd supervisor, worker, independent attester and witness;
   record initial/terminal PID and starttime, service MainPID, cgroup journal,
   checkpoint, denial of replay and no orphan scanner processes.
5. Have a separate externally provisioned hardware TPM2 monotonic root and
   atomic one-use recovery permits. Prove rollback to genesis, concurrent
   recovery admission and authority crash/restart under independent UIDs.
6. Obtain actual site-owner signed lab scope for an exact job attempt,
   environment constraints and limited duration. Confirm the target is
   authorized before any network test; never reuse test-generated signatures.
7. Preserve stdout/stderr, exit statuses, timing, kernel/systemd MAC logs,
   content hashes, complete tests, machine identity, authority signatures and
   all negative results. Without this evidence, remain BLOCKED/NO-GO.

## Threats and residual risks

Environment flags, Python import guards and filenames cannot confine same-UID
legacy tools. cgroup migration can defeat `cgroup.kill`; POSIX process groups
alone cannot contain double-fork and setsid escapes. PID reuse may defeat
numeric PID signals (Stage 62 uses pidfd). Underlying Linux and policy files
must be immutable against the scanner's own UID; attester and publisher cannot
share credentials with the worker. A signed JSON counter is not a hardware
witness, and a passing unit-test suite cannot establish OS-enforced MAC.

Current customer-production decision: **BLOCKED/NO-GO**.
