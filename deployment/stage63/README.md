# Stage 63 review-only Linux host commissioning plan

These files are **proposals**. They do not install the four independent services,
load MAC policy, issue signing keys, or authorize active security scans.

1. Use a dedicated test Linux host (PID 1 systemd, cgroup v2 with delegated writable
   subtree, kernel `cgroup.kill`, `pidfd_open`, `pidfd_send_signal`).
2. An independent administrator provisions separate non-root UIDs:
   `cybersec-worker`, `cybersec-attester`, `cybersec-witness`, `cybersec-publisher`.
   A worker must have no access to witness/publisher signing keys.
3. Independently review/compile/install enforce-mode AppArmor or SELinux policies.
   In particular, transition the Nuclei executable to a restrictive scanner domain,
   deny that domain writes to `cgroup.procs`, `cgroup.kill`, sibling service files,
   all signing keys, Git credentials and coordinator state. Restrict alternative
   interpreters, exec paths and privileged/unconfined same-UID startup.
   Profiles cannot be considered verified merely because files exist.
4. Independently deploy and audit all four service executables and systemd
   units. Neither attester/witness/publisher binaries nor a hardware monotonic
   authority are present in this source release. Do not enable placeholder units.
5. An owner of the **isolated loopback lab** issues a real Ed25519 per-attempt
   permit, independently pinned under `/etc/cybersec/trust/` with root-only
   provisioning. The operator must verify lab ownership, operator consent,
   expiry and exact scope. The signed sample tests are synthetic and do not
   authorize a scan.
6. Run `python -m cybersec.stage63_host` as a read-only inventory. Exit 3 means
   BLOCKED/NO-GO, including on a positively configured host until independent
   negative OS-enforcement and restart proofs are imported and verified.
7. Under independently controlled UIDs, run signed authorization + safe
   sentinel (not Nuclei) end-to-end checks: `setsid`, double-fork, PID reuse,
   stop/restart, cgroup PID escape attempt, and `SIGKILL` after checkpoint/CAS.
   Collect raw `journalctl`, `/proc`, `systemctl show`, cgroup events, LSM audit,
   original signed authority evidence and SHA-256, including all FAIL cases.
8. Verify hardware-backed durable anti-rollback root and one-use recovery
   permit consumption. `cybersec.recovery_authority.verify_recovery_receipt`
   only verifies a signed envelope and MUST NOT grant execution rights.
9. No universal ZAP remote-daemon cancellation is established. ZAP and sqlmap
   are not production-admitted by Stage 63.

A VM or local container without externally controlled LSM and monotonic
witness remains NO-GO. No active network scanning is performed by tests.
