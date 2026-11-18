# Cyber Security 2.0 — Stage 70 / v2.50.0: verified status

**Status: BLOCKED / NO-GO — laboratory evidence only.**

## Source provenance
- Cumulative package: `cyber_securuty_2.0_stage_70_crypto_mmap_hotfix.zip`
- Package SHA-256: `5a53d945de881a418cc2d61bbf0f43bdb1df8df0769acf38662193fa295a6e46`
- Package integrity verified: 762 entries, ZIP CRC PASS.
- Previous cumulative archive: 739 inherited entries; 499 historical evidence files SHA-preserved.
- Version remains Stage 70 / v2.50.0; **no new Stage**.

## Verified local regression evidence
| Run | Passed | Skipped | Failed | Exit |
| --- | ---: | ---: | ---: | ---: |
| strict #1 | 639 | 69 | 0 | 0 |
| strict #2 | 639 | 69 | 0 | 0 |
| strict #3 | 639 | 69 | 0 | 0 |

Warning filters: `ResourceWarning` and `DeprecationWarning` as errors. The 69 Ubuntu opt-in tests were *not* run in the local environment. Historical PASS/FAIL and diagnostics remain preserved in the private cumulative archive.

## Actual Ubuntu observations, 2026-11-18
- Ubuntu 26.10 and Python 3.14.8; five separate service UIDs.
- Six Stage 70 AppArmor policies passed Ubuntu 26.10 strict offline parse with `--Werror`; `kernel_mac_evidence=false` at that stage.
- Current hotfix contains a nine-file approval manifest requirement; the earlier installed baseline verified eight pinned files as `LAB_MANIFEST_VERIFIED_NOT_ATTESTED`. Approval/installation of the nine-file hotfix has **not** been proven.
- Earlier Ubuntu runtime evidence showed **five failed laboratory systemd services** (`start-limit-hit`) caused by import-time `cryptography` Rust shared object executable mapping failure.
- Current source hotfix narrows the AppArmor `m` permission to the required Rust extension and includes a guarded `upgrade` path, but **no post-upgrade Ubuntu runtime success evidence has yet been received**.

## Follow-up Ubuntu lab snapshots — 2026-11-18 (private originals)
Validated both outer SHA-256 sidecars, ZIP CRC and all three internal SHA records in each snapshot.

| Capture UTC | Archive SHA-256 | Services active | PID/label/cgroup | Kernel DENIED |
| --- | --- | ---: | --- | ---: |
| 16:30:50 | `9cdc7c372256fdb94b50001dde707f6429e2af58d3568274556363db6571d8ab` | 0/5 | unavailable for all five | 0 |
| 18:07:43 | `92edab1305ee1c07dbe7e19b4238439bc048a01263eb2d2cb9ad6bbf85404433` | 0/5 | unavailable for all five | 0 |

Both archive reports state `BLOCKED/NO-GO`. Their structured observations match apart from capture timestamp. A separate uploaded runtime status file (SHA-256 `c02c2a6919da906ef79788a419011c21e9590fbff6d61b3fe4d3ce716174a584`) confirms the earlier `_rust.abi3.so` executable mapping error, `start-limit-hit`, and five `MainPID=0`. **Neither snapshot proves that the guarded `upgrade` ran or that the hotfix failed after a confirmed successful upgrade.** Zero observed `DENIED` is not a PASS for the required negative MAC test.

## Git repository publication boundary
As of this evidence update, the default branch contains this sanitized status report, but the complete Stage 70 application source ZIP has **not** been verified as published in the default branch. Do not equate this evidence commit with the full source push.

## Release blockers
- Five *running* lab service PID/UID/cgroup/enforcing MAC labels are unverified after the hotfix.
- Independent kernel AppArmor DENIED, `SO_PEERCRED`/`SO_PEERSEC` cross-UID/same-UID tests, SIGKILL lifecycle and full Ubuntu opt-in acceptance remain unverified.
- Independent protected monotonic witness root, production service graph and production admission remain absent/unproven.
- The lab-only probe services do not scan, issue permits, mutate witness CAS or publish results. `HostAdmission.check()` continues to deny production.

This public report intentionally excludes raw host journals, private Ubuntu evidence archives, machine-specific diagnostics and secrets. **Publication of a report does not imply publication of the complete 762-file source ZIP or production acceptance.**

## CFFI executable mapping follow-up — source hotfix (still NO-GO)

Ubuntu runtime diagnostic captured **2026-11-18 18:20:18 UTC** (private original SHA-256 `25d8b7d891a733252cc29aeac8e23550381d5a8f44cb2d66f0d538f65ccea9e2`) confirms that the five installed policies have the previously added Rust `mr` permission and valid nine-file root-owned manifest (`verify` exit 0), but all five lab instances still fail to start. The import now fails on the *different* `_cffi_backend.cpython-314-aarch64-linux-gnu.so` native extension (executable mmap). The five failed services remain historical Ubuntu FAIL, not post-remediation PASS.

**New cumulative package prepared locally, NOT yet pushed as source files:** `cyber_securuty_2.0_stage_70_cffi_mmap_hotfix.zip` with SHA-256 `ab28221525fc65b80b77115d4945d4a68db5a03b28a76b3ee35490439a2f6e0c`, 784 files; 762 previous files preserved, 520 historical evidence files byte-identical. Exact `mr` for the identified CPython 3.14/aarch64 CFFI extension is added to the five LAB profiles. The guarded updater recognizes only the five observed previous policy digests, checks root-owned runtime extension and requires fresh pinned approval. No automatic service restart or production admission bypass is included.

**New offline strict cumulative regressions:** 3 runs of **649 PASS / 69 SKIPPED / 0 FAIL**, exit code 0, `ResourceWarning` and `DeprecationWarning` treated as errors. These do not establish Ubuntu kernel enforcement or actual successful service startup. Independent root, production service graph and complete Ubuntu opt-in acceptance still **BLOCKED/NO-GO**. Private Ubuntu journals and host-specific evidence are not published to this public repository.
