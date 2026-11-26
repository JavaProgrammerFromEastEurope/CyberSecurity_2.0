# Stage 65 — OS-enforced separation candidate (review only, NO-GO)

**No units are installed or enabled.** This directory is a deployment contract,
not an authorization for any scanner. Ubuntu Server **26.10** opt-in test host
and independent operator must review all paths, UIDs, signatures and MAC rules.

Expected separate non-root UIDs: `cybersec-worker`, `cybersec-attester`,
`cybersec-witness`, `cybersec-publisher`; plus `cybersec-broker`. Do not share
service-user identities, groups with write authority, private directories or
signing key custody. The worker must not be able to write a sibling's state.

`cybersec host65-preflight` and `python -m cybersec.stage65.preflight` exit **3**.
Stage 64 `host-preflight` and all legacy production scanner gates continue to
refuse execution. The Stage 65 `service --role broker` also exits **3** before
binding its socket until independent kernel/OS evidence and a future explicit
release gate are integrated. The witness service is **lab opt-in only**.

## Service contracts

- Root-owned `/etc/cybersec/stage65.json`: immutable allowlist of absolute
  executable paths and complete argv (no shell / dynamic request parameters),
  pinned attester Ed25519 public key, root-owned `installed_policy` pathname,
  pinned SHA-256 of loaded MAC policy, real cgroup delegation;
  immutable service account mappings / socket groups, no secrets or private keys.
- The attester signs canonical per-attempt permits (ID, worker UID, scope,
  generation, argv digest, validity <5 minutes). The attester signing key lives
  under a separate UID, never in worker/broker/witness directories.
- Broker Unix socket: peer UID from SO_PEERCRED must equal worker UID. Only
  pinned-manifest commands may run; no caller-supplied arbitrary argv.
- Witness Unix socket: peer UID from SO_PEERCRED must equal broker UID. CAS is
  serialized and fsync-backed; worker cannot access witness socket or DB.
- For cross-UID sockets, configure dedicated non-sensitive socket access groups.
  Only socket inodes are group writable; DB/private keys must remain owner-only.
  SocketGroup / ACL installation must be reviewed; the server refuses symlinks.
- Kernel cgroup broker is separately delegated (systemd `Delegate=yes`) into a
  writable subtree; child Python trampoline reads a one-byte gate. Parent uses
  `pidfd_open`, double-observes PID start ticks, moves paused child into a fresh
  `scan-<permit-id>` cgroup, verifies placement, then releases the exec gate.
  On timeout/error it writes `cgroup.kill`, waits for `populated 0`, reaps the
  leader, refuses uncertain descendants. Broker cold restart cleans orphaned
  `scan-*` children before issuing new claims.
- systemd manager must be independent of broker, with
  `KillMode=control-group` / `SendSIGKILL=yes` and explicit restart semantics.
  Service manager must kill descendants even when broker is SIGKILLed.
- Witness CAS is durable against process crash, **not privileged filesystem
  rollback**. A TPM NV monotonic root or independently hardened trusted remote
  witness with anti-rollback attestation is still mandatory for production GO.

## Lab tests

Run only after root-controlled OS profile and fixture provisioning:

```bash
CYBERSEC_UBUNTU_2610_TESTS=1 \
CYBERSEC_STAGE65_TEST_DELEGATED_CGROUP=/sys/fs/cgroup/... \
python -W error::ResourceWarning -W error::DeprecationWarning \
  -m pytest -q tests/integration/test_stage65_ubuntu.py
```

Additional targeted destructive and MAC negative probes require separate
fixtures / opt-in (see `docs/STAGE_65_OS_ISOLATION_RECOVERY.md`). No ZAP,
Nuclei, sqlmap, remote target or non-fixture scanner is executed.
