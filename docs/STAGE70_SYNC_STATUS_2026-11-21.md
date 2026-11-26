# Stage 70 integration ledger — 2026-11-21

## Git provenance

Base branch: `stage65-v2.45.0`, commit `6b9f8334b8c987e5469a929fe400a3599cc43ebf` (350 files). Repository default `prework_cybersecurity`, commit `5ad394e7478f819c9e5d7e4e3a21956afcdfb6b7`, is divergent and contains one newer historical Stage70 sanitized report. This branch retains that report without overwriting either original branch.

## Confirmed laboratory changes

- Stage70 CFFI / Rust import permissions were repaired and five LAB process start checks passed.
- Chrony synchronization restored following correction of the VM system clock.
- v14 five-role LAB startup passed, but AppArmor originally denied termination signals from systemd.
- v16 broad signal-receive permission fixed LAB shutdowns but v17 confirmed 5/5 unauthorized same-UID SIGTERM.
- v20 profiled-controller prototype passed 5/5 tests; v21 confirmed 5/5 same-UID controller-profile impersonations.
- v23.3 replaced the broad signal receive rule with five restricted LAB policies and passed five negative same-UID SIGTERM checks.
- v24 bounded lifecycle test is prepared and locally tested; no real v24 VM execution verified at synchronization time.

## No premature production promotion

The VM-only `exact_enforcing_mac` patch accepting stacked `//&unconfined` labels does not have independent confinement assurance and is intentionally not merged into `src/cybersec/stage65/host.py`. Likewise, the experimental LAB policies are not automatically installed by this branch.

**PRODUCTION=BLOCKED/NO-GO; G01–G10 accepted PASS=0/10; Stage 71 NOT_OPENED.**

Still required: independently protected lifecycle authority, non-impersonable label transition, end-to-end cross-UID IPC, protected witness/rollback root, crash/restart proofs, and all 92 scenarios defined in the complete specification. Local test counts and ZIP integrity do not replace production acceptance.

## Policy SHA-256 from verified v23.3 source bundle

- broker: `3fbd378f1f9c26d5df2ed06707f2d5962b10866f3ce485a1ef28f152c171f77c`
- worker: `d2f16d78a09308fea3dcaa698940d68cb507d8677e6bf57900dd823fb2836ac6`
- attester: `9aa4146e4c649dfb23710cfe7268492904e68886708783ab16ea748cf085e583`
- witness: `25bcadacbd169d3ebb45acbe96ae210ec926a6603eae98f0f39f40a43e4edcda`
- publisher: `a531b11a2d3135f22c59eb56353199e967329c36b1d1f604d53a139987016d37`

Raw VM logs and ZIP evidence are excluded from public GitHub for privacy and safety.
