# Stage 65 / v2.45.0 — OS-Enforced Isolation, Cross-UID Admission & Durable Recovery

**Decision: BLOCKED/NO-GO.** This stage implements enforceable admission *primitives*,
contracts and opt-in host probes. **No Ubuntu Server 26.10 installation was
performed, no AppArmor profile or systemd unit loaded, no scanner executed.**
There is no production authorization bypass or release GO in this archive.

## Provenance and compatibility

- Exact source: user-provided `cyber_securuty_2.0_stage_64(1).zip`, SHA-256:
  `78ed1e34f49fbe3006d43d6801fa66fbd497b4a3f9e809b6288c43efcef0bddb`.
- Stage 64 project files and evidence retained. The existing `cybersec` APIs,
  Stage 61 PDF (`pdf_reports.py`), offline evidence APIs, SQLite application
  schema, CLI commands and scanner-worker integrations are unchanged except
  additional `host65-preflight` and version metadata. The Stage 65 permit/witness
  ledger uses separate SQLite databases; no application DB migration.
- New modules in `src/cybersec/stage65/`; new Stage 65 docs, opt-in test and
  review-only unit candidates in `deployment/stage65/`. Existing Stage 64
  production gate (`production_admission.require_production_admission`) continues
  to refuse production execution in every legacy entrypoint.

## Architectural authority / trust boundaries

```text
 customer authorization & static root-owned manifest
                |
 independently confined attester UID -- Ed25519 signed attempt permit
                |
 worker UID -- AF_UNIX / SO_PEERCRED --> independent broker UID
                                               |
       pinned issuer key + exact immutable argv digest + UID/scope/generation
                                               |
  HostAdmission: Ubuntu 26.10 + actual MAC/systemd + trusted acceptance
       (Stage65 ALWAYS NO-GO pending kernel negative acceptance)
                                               |
            durable one-use intent journal (SQLite FULL/WAL)
                                               |
     witness UID -- AF_UNIX / SO_PEERCRED --> separate SQLite CAS head
                                               |
                 root-provisioned cgroup v2 subtree
                                               |
                   gated Python trampoline
                  pidfd + startticks + cgroup
                                               |
                exec only after placement proof
                                               |
                cgroup.kill + cgroup.events
                                               |
 publisher UID: read-only evidence, no permit/scanner authority
```

This is an **implementation separation**, not deployed four-UID enforcement.
The broker itself has a fifth independently isolated UID. Worker cannot sign
permits; attester cannot write witness; publisher cannot execute scanner.
MAC requirements appear in `deployment/stage65/APPARMOR_MAC_CONTRACT.md`.

## Requirements and traceability

| ID | Requirement | Code / contract | Local evidence | Ubuntu acceptance |
|----|-------------|-----------------|----------------|-------------------|
| S65-REQ-01 | Preserve cumulative releases, PDFs, API and DB | Unchanged Stage 64 tree, version only and CLI extension | Three strict full tests + SHA manifest | Pending deployment proof |
| S65-REQ-02 | Canonical signed one-use permit, <=5 min | `contracts.Permit`, `PermitVerifier`, Ed25519 domain separation | Test signature, expiry, scope, command, UID, replay | Independently protected attester key and audit |
| S65-REQ-03 | Atomic witness CAS, persistent recovery | `ledger.WitnessLedger`, `witness.WitnessStore`, `SocketWitnessAnchor` | Real local SIGKILL before/after CAS; SQLite rollback and restart | Cross-UID witness, real `SIGKILL`/filesystem rollback and TPM monotonic anchor missing |
| S65-REQ-04 | Independent socket-bound UID admission | `broker.AdmissionBroker`, `UnixAdmissionServer`, `witness.peer_uid` | Mismatched UID refused before permit consumed | Real worker/attester/witness/publisher UID negative probes pending |
| S65-REQ-05 | Pre-exec cgroup attachment and subtree kill | `KernelCgroupBroker`, `trampoline` | Source compilation and opt-in Ubuntu fixture (not run here) | Real delegated cgroup v2, setsid/double-fork, cgroup.kill, PID identity |
| S65-REQ-06 | Mandatory OS-enforced legacy fencing | Stage 64 `production_admission`, Stage 65 `host.HostAdmission`, AppArmor contract | Production rejects independent of environment-positive probes | Kernel audit same-UID bypass denied under enforce profile; missing |
| S65-REQ-07 | Independent systemd restart / cleanup | `KernelCgroupBroker.recover_orphans`, candidate units | Real local SIGKILL witness recovery | systemd transient unit SIGKILL/restart on Ubuntu 26.10; missing |
| S65-REQ-08 | Non-destructive reproducible evidence | `tests/test_stage65_contracts.py`, `tests/integration/test_stage65_ubuntu.py`, strict runner | Three strict log sets in `evidence/stage65` | Four-UID systemd/AppArmor/TPM independent evidence not collected |

## Atomic permit and recovery protocol

1. Operator approves an already authorized scope and an immutable command
   manifest. **Separate attester** creates Ed25519 signature over canonical JSON
   (schema, ID, attempt, target worker UID, scope, `argv_sha256`, generation and
   issued/expires timestamps). Broker pins the public key, not the private key.
2. Broker checks Linux `SO_PEERCRED` worker UID, maps command to its **server-owned**
   exact argv, verifies scope/generation/signature/time, then calls the
   mandatory host admission gate. No trust of caller-supplied UID or argv.
3. Before any spawn, ledger executes `BEGIN IMMEDIATE`, checks independent
   anchor equals local committed head and records an irreversible `pending`
   claim with digest of prior head + attempt context. SQLite uses WAL and FULL
   synchronous. No external scan may run while pending.
4. A separate witness UID atomically CAS-advances the head to the new sequence
   and digest. After that, ledger atomically finalizes claim as `used`. Only
   after step 4 may a broker create a scanner scope.
5. Recovery: if pending head is already externally advanced, finalize as USED;
   if external head is unchanged, retire pending as ABORTED; all ambiguous
   states including a local rollback yield `LedgerBlocked`. No automatic
   retry of any uncertain or consumed attempt.
6. Broker cold restart cleans all `scan-*` cgroups via `cgroup.kill` before
   accepting further operations. Host systemd must separately kill the broker's
   descendants even if the broker itself is SIGKILLed.

### Crash/state matrix

| Crash boundary | Witness head | Recovery decision |
|---|---|---|
| Before DB pending commit | Old | No claim (no scanner has executed) |
| After pending DB commit / before witness CAS | Old | Retire pending, reject reuse |
| During witness CAS | Old or new | Retire or finalize, never execute uncertain command |
| After witness CAS / before DB USED commit | New | Finalize USED, reject reuse |
| After DB USED / before scanner pre-exec | New | Remains USED, no automatic replay |
| After pre-exec release / SIGKILL broker | New | Only independent systemd+cgroup cleanup may bound children; no retrial |
| SQLite replay/rollback with witness new | New | Refuse startup or new attempt (NO-GO) |
| Attacker rolls back both DB and witness state | Unknown | **Unprotected without independent monotonic root; production NO-GO** |

## OS isolation constraints and unresolved hazards

- A cooperating Python caller cannot prove own MAC containment. AppArmor must
  deny **all** alternative same-UID execution routes including legacy API,
  interpreter, namespace escape and cgroup migration. Merely reading
  `/proc/self/attr/current` does not prove a kernel-denied negative test.
- `CgroupV2Broker` can attach a trampoline pre-exec under independently
  delegated PID1 service and inspect start ticks. No Python user-space check
  can atomically forbid post-attach cgroup migration without MAC enforcement.
- The Stage 65 witness SQLite CAS is crash-durable but can be rolled back by a
  sufficiently privileged filesystem adversary. Real independently monotonic
  TPM NV / secured hardware or trusted remote root plus key attestation is
  not implemented. SQLite WAL/fsync is not a substitute for anti-rollback.
- The attester's private key must be generated and protected by the attester
  UID *outside* the archive. No release private keys or live permits are
  packaged. `InMemoryAnchor` is test-only and actively rejected by broker.
- Role setup, AppArmor profiles, unit lifecycle, broker socket groups and
  root-owned allowlist need actual Ubuntu host provisioning and audit.
- The Stage 65 production gate remains unconditional NO-GO until independent
  acceptance is approved in a subsequent audited release. Do not patch out the
  gate, mark unit candidate operational, or manually bypass the legacy guard.

## Real opt-in Ubuntu Server 26.10 tests

The integration module is **not** runnable against this build host; it is
activated only with `CYBERSEC_UBUNTU_2610_TESTS=1`. On a provisioned Ubuntu
Server 26.10 host it requires explicit delegated cgroup path and independent
service UIDs. It checks PID starttick identity/reuse negative, real cgroup.kill,
setsid, double-fork, concurrent startup and recover_orphans, real runuser
cross-UID process identities, production fail-closed refusal. Extra opt-ins:

- `CYBERSEC_STAGE65_DESTRUCTIVE_TESTS=1` creates its own transient
  `cybersec-stage65-fixture-*` unit and performs actual main-PID SIGKILL and
  systemd restart verification; never modifies pre-existing user services.
- `CYBERSEC_STAGE65_MAC_NEGATIVE_TESTS=1` and
  `CYBERSEC_STAGE65_LEGACY_NEGATIVE_FIXTURE=/absolute/path` attempt an
  independently provided worker-UID legacy bypass and require a correlated
  `journalctl -k` AppArmor DENIED record. A refusal string from the test process
  alone is insufficient. The fixture must be root-controlled and vetted.
- Additional independent tests are still required for cgroup migration denial,
  socket spoofing with actual role UIDs, permits under real attester/witness,
  physical rollback and service-manager restart of *all* five services.

No ZAP, Nuclei, sqlmap, live scan or network-target action appears in these
opt-in tests. The three locally completed full regressions run without opt-in
and therefore cannot satisfy any of the missing Ubuntu acceptance checks.

## Test and evidence interpretation

Each strict full regression treats `ResourceWarning` and
`DeprecationWarning` as errors, archives stdout, stderr, code, classification,
execution time and SHA-256 of logs. Full source manifest hashes all cumulative
files except its own manifest. Prior Stage 61–64 evidence stays unmodified.
A passing Python test is not evidence of the kernel safety property.

**Current production status: BLOCKED/NO-GO.** Next Stage 66: identity/RBAC,
secrets, cryptographic scope and cross-service authorization; do not mistake
Stage 66 completion for lifting the Ubuntu production safety gate.
