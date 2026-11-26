# Stage 64 Ubuntu 26.10 — deployment candidate, NOT a production service

The systemd unit is **reference-only**. It is intentionally non-operational:
`ConditionPathExists` must be installed by an independent administrator and
`ExecStartPre` always returns 3 (`BLOCKED/NO-GO`). Do not modify the preflight
or make this a production service to make a test pass. Both the unit and app
contain runtime checks, neither is sufficient to stop unconfined same-UID
legacy subprocess entrypoints. No AppArmor policy is distributed as an
"enforcing" profile; see `APPARMOR_AND_CGROUP_CONTRACT.md`.

## Ubuntu 26.10 evidence collection (read-only)

1. Provision a disposable Ubuntu Server **26.10** host with Python **3.14**,
   OpenSSL **4.x**, systemd **261.x**, unified cgroup v2 and AppArmor enabled.
   Capture `/etc/os-release`, Python and OpenSSL versions, `systemctl --version`,
   `cat /proc/1/comm`, the kernel release, LSM stack and service UIDs.
2. Use an independent administrator to review/ensure real MAC confinement,
   specific role identities and trusted admission authority; importing this
   tree does not provision any of them.
3. Install *dependencies only* in an isolated Python environment, verify
   cryptography and ReportLab wheels for CPython 3.14/OpenSSL 4, and run
   `python -W error::ResourceWarning -W error::DeprecationWarning -m pytest`
   without calling real scanners.
4. Run `python -m cybersec.stage64_runtime` or `cybersec host-preflight`. Both
   return 3 regardless of observed readiness. Save JSON, stderr and exit code.
5. Manually inspect the candidate unit with `systemd-analyze verify`; do not
   start or enable it as part of Stage 64. Collect unit properties only for
   independently deployed, operator-controlled services.
6. For opt-in local Python fixture checks, explicitly set
   `CYBERSEC_UBUNTU_2610_TESTS=1` and run
   `python -m pytest -q tests/integration/test_stage64_ubuntu.py`.
   These exercises use Python only and do not start network scanners.
7. Run separately supervised kernel MAC *negative* tests and cgroup restart
   tests on a dedicated systemd unit after provisioning it; all output and
   kernel audit denials are required for the next stage. A simulated or
   missing host check cannot establish production GO.

## Technical risks

`KillMode=control-group` is managed by PID 1 systemd; an unconfined child
could leave the service cgroup through an allowed migration API. PID +
starttime only detects some PID reuse races and cannot replace pidfds for
signal authority. SIGKILL on a worker may leave an escaped process; OS-MAC
and cgroup v2 negative proofs must be collected on the real host.

Stage 64 deliberately includes no `cgroup.kill` writer and does not issue
unsigned or locally minted permits. The production operation is blocked.
