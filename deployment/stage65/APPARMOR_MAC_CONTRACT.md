# Stage 65 AppArmor/MAC contract — BLOCKED/NO-GO

**Not an installed AppArmor profile.** Synthetic or permissive profiles do not
count as MAC enforcement. Separate kernel-enforced profiles must be compiled,
installed from trusted root-owned paths, loaded in enforce mode, and backed by
observed independent negative tests. Exact executable paths and hashes are
host-specific and must not be guessed in a generic distribution archive.

| Principal | MAY | MUST NOT |
|---|---|---|
| worker | Connect to broker socket and read own authorized job metadata | Access attester signing key, witness DB/socket, cgroup controls, direct scanner exec, publisher credentials, legacy production bypass |
| attester | Sign approved scope-bound per-attempt permit using private Ed25519 key | Spawn scanner, edit witness ledger, manage broker, publish results |
| witness | Verify broker SO_PEERCRED and atomically advance signed/verified monotonic head under separate UID | Sign permits, run scanners, allow same-UID worker writes, accept rollback |
| publisher | Read verified export/evidence and publish through approved egress | Issue/consume permits, execute scanner, modify witness chain |
| broker | Validate worker peer UID, pinned commands, signed permit and witness, attach blocked trampoline to delegated cgroup | Read attester private key, exec arbitrary caller command, escape its service cgroup, alter LSM/systemd policy |

Critical kernel negative tests (record actual errno and kernel audit): same-UID
unconfined Python/legacy scanner direct launch, broker policy substitution,
worker/scan child write into `cgroup.procs` outside delegated subtree,
`setns`/`unshare` profile escape, witness-state or attester-key access,
unauthorized Unix-socket impersonation, and network outside approved sandbox.
Every negative test MUST be demonstrated under the real service UID and loaded
profile, and include matching `journalctl -k` / auditd evidence. A printed
`DENIED_BY_KERNEL` string alone is not independent evidence.

**Do not turn off** the Stage 64 production admission guard to perform a test.
If the full kernel evidence cannot be collected, report BLOCKED/NO-GO.
