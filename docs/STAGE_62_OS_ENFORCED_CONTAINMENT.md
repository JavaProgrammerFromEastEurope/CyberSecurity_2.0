# Stage 62 — OS-Enforced Scanner Containment & Authorized Lab Recovery (v2.42.0)

## Scope and requirements

| ID | Requirement | Code / verification | Result |
| -- | -- | -- | -- |
| C62-01 | No scanner exec without delegated writable cgroup v2, `cgroup.kill`, systemd and MAC | `cgroup_containment.CgroupV2Executor._preflight` | Fail-closed locally; no supported host available |
| C62-02 | Atomic scanner pre-exec placement | Parent starts Python trampoline on a closed pipe; verifies PID starttime before/after migration and `/proc/PID/cgroup`, then opens gate | Incorrect gate, EOF and wrong membership tests PASS; true cgroup E2E unavailable |
| C62-03 | Cancellation across `setsid` / double-fork | Dedicated child cgroup; `cgroup.kill`, verify `cgroup.events populated=0` | Kernel implementation path present, not host-qualified; MAC escape prevention unproven |
| C62-04 | PID reuse / stale completion | PID starttime/membership check; Stage 58/59 atomic SQLite fencing | Negative tests PASS |
| C62-05 | Strictly authorized local lab | Root-pinned Ed25519 per-attempt ticket for literal 127.0.0.0/8 or ::1 target | Synthetic cryptographic verification PASS; no external ticket issued |
| C62-06 | No generic active ZAP/sqlmap, no legacy direct scanner production | Production-mode direct guard; ZAP daemon + SQLmap blocked | Python API negative tests PASS; OS-enforced legacy MAC absent |
| C62-07 | SIGKILL worker / service manager restart | Stage 60 manual recovery, proposed systemd `KillMode=control-group` and `Delegate=yes` | Real restart and cgroup.kill after host SIGKILL NOT proven |
| C62-08 | API and schema compatibility | Existing `run_supervised`, Nuclei direct dev API, DB APIs retained | Full pytest regression |

## Trust and threat model

Stage 62 separates a **dev/test library path** from a *candidate* production
execution path. `CYBERSEC_EXECUTION_MODE=production` is not an OS security boundary;
a same-UID actor could unset it or invoke old scanner code. Only a verified
systemd + MAC/LSM policy that disallows all unauthorized exec paths and
`cgroup.procs` migration can close that bypass. The shipped systemd unit is
review-only; it is not installed. The four service UIDs, keys, immutable
lab-tickets and independent supervisor are not available here.

The scanner process starts as a Python trampoline awaiting a one-byte permit
through an inherited FD. The parent moves the sleeping process into a fresh
child cgroup and verifies both the exact cgroup and PID starttime. Without
`b'1'` or if the parent crashes early, scanner exec is denied. On local abort,
the parent signals the process group then uses kernel `cgroup.kill`, checks
`cgroup.events populated=0` and refuses to report clean completion if
surviving descendants remain. Exit status is not a proof of external network
side effects being rolled back.

Potential residual risks: host privileges may allow migrating processes to a
different cgroup; `cgroup.events` only describes members of the one cgroup;
therefore independent MAC and `/proc` observation from another UID are needed.
The pre-exec handshake limits races but does not replace audited service
manager recovery when the worker dies *after* releasing the child. A signed
lab ticket is not by itself a consent record from a real lab owner.

## Fail-closed behavior

* Missing or read-only cgroup v2, missing independent systemd, missing kernel
  `cgroup.kill`, unenforced LSM => block *before* scanner process creation.
* No independently root-pinned Ed25519 ticket bound to job+attempt+URL => block.
* No actual production MAC or signed external owner approval => production NO-GO.
* ZAP passive polling cancellation does not stop its remote daemon: blocked in
  production; no remote action against an uncontrolled daemon.
* Nuclei fixed conservative tags/rate limits and output scope filter remain.
  No active scanner tests are executed on external targets in this stage.
* The preexisting `request_manual_scan_recovery` is retained; it must not be
  treated as independent proof of killed descendants. Never auto-replay Nuclei.

## Test evidence and limitations

The new tests perform *real local* Python trampoline/FD and SQLite scenarios,
plus adversarial signature and scope inputs. Host audit is read-only. We do
not synthesize a writable cgroup mount or report fake MAC/systemd success.
Three full strict regressions use `ResourceWarning` and `DeprecationWarning`
as errors and record stdout, stderr, exit code and the SHA-256 of all artifacts.

**Production: BLOCKED/NO-GO** until a truly independent Linux lab proves four
UIDs, OS MAC, delegated cgroups, kernel cgroup.kill after setsid/double-fork,
crash/restarter completion and signed permission to scan a loopback lab.
