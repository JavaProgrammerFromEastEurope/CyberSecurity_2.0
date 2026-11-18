# Cyber Security 2.0 — Ubuntu Stage 70 post-hotfix evidence audit

**Verdict: BLOCKED/NO-GO.** Analysis completed 2026-11-18. This is a sanitized analysis, not a claim of OS-MAC/production acceptance.

## Integrity

| Artifact | SHA-256 | ZIP / nested ZIP | Internal manifests |
|---|---|---|---|
| `stage70_ubuntu_evidence_all(1).zip` | `ed36c8ee0826ffb0962057a5e443a897761843d77a26baa96a3f1ceff64b1d1a` | PASS; 4 nested archives | 76 / 76 PASS |
| `stage70_ubuntu_evidence_updated.zip` | `e1bb154f07733dfc09bc8875b6b62cbaaa7029c6ef6fee5dae2770cdded244b3` | PASS; 7 nested archives | 133 / 133 PASS |

All 88 non-directory members from the original collection are present byte-identically in the updated collection. External SHA-256, ZIP CRC, nested ZIP SHA-256 and per-file internal SHA-256 were verified. Integrity does not establish authenticity of the original test host.

## Full strict regression history

All 21 full regressions used the saved flags treating ResourceWarning and DeprecationWarning as errors. "Skipped" Ubuntu integration tests are **not** production evidence.

| Run created (UTC) | Strict #1 | Strict #2 | Strict #3 | Overall |
|---|---|---|---|---|
| 2026-11-17 20:28 | 548P/3F/49S (exit 1) | 548P/3F/49S (exit 1) | 548P/3F/49S (exit 1) | BLOCKED |
| 2026-11-17 20:30 | 548P/3F/49S (exit 1) | 548P/3F/49S (exit 1) | 548P/3F/49S (exit 1) | BLOCKED |
| 2026-11-17 20:58 | 548P/3F/49S (exit 1) | 548P/3F/49S (exit 1) | 548P/3F/49S (exit 1) | BLOCKED |
| 2026-11-17 21:07 | 548P/3F/49S (exit 1) | 548P/3F/49S (exit 1) | 548P/3F/49S (exit 1) | BLOCKED |
| 2026-11-17 21:41 | 551P/0F/49S (exit 0) | 551P/0F/49S (exit 0) | 551P/0F/49S (exit 0) | TESTS_COMPLETE |
| 2026-11-18 13:10 | 551P/0F/49S (exit 0) | 551P/0F/49S (exit 0) | 551P/0F/49S (exit 0) | TESTS_COMPLETE |
| 2026-11-18 13:28 | 550P/1F/49S (exit 1) | 551P/0F/49S (exit 0) | 551P/0F/49S (exit 0) | BLOCKED |

**Totals:** 21 completed strict regressions: 8 PASS and 13 FAIL. The first 12 failures (4 sets × 3) were from three missing TrueType-font tests. Six complete successful regressions subsequently verified the PDF-font remediation on the real Ubuntu VM. The newest set has one intermittent failure in the first run; its two later runs passed, but the set's overall verdict is BLOCKED.

## Remaining intermittent regression

`tests.test_stage66_replay_secrets::test_stage66_unix_peer_uid_kernel_and_generic_denial` failed once with `ConnectionRefusedError: [Errno 111] Connection refused`.

Source inspection shows the test waited for `Path.is_socket()` and then called `connect()`. The server calls `bind()`, then `chmod()`, then `listen()`. A path can exist before `listen()` is active. This is consistent with a startup-ordering test race, not proof of broken SO_PEERCRED, yet must not be dismissed until a bounded, fail-closed readiness test is verified.

**Proposed correction:** In this test only, use a monotonic 3-second deadline to retry connection on only `FileNotFoundError`/`ConnectionRefusedError`; fail immediately if the server thread dies, the deadline elapses, or any other socket error occurs. Add deterministic positive and negative tests (delayed `listen()` and server never listening). Do not modify production admission semantics.

## Independent production blockers

The newest `ubuntu_prerequisites.json` reports Ubuntu Server 26.10, AppArmor kernel, cgroup v2/cgroup.kill, systemd PID1 and distinct UIDs; however `controller_mac_enforcing=false` and `root_fixture_controller=false`. The Stage 70 run mode is `local`, production_admitted=false and release_authorization=false, with 49 Ubuntu opt-in tests skipped in **every** full run.

A local PASS cannot confirm mandatory Ubuntu 26.10 AppArmor DENIED tests, UID service-manager isolation, independent monotonic root or complete publication/service crash recovery.

## Additional note on hotfix application

The uploaded successful Ubuntu runs contain 600 collected cases (551 PASS + 49 SKIPPED). The previously supplied Stage 70 Ubuntu hotfix adds a test for the fixture-environment contract, so its expected local count before this socket test correction is 601 (552 PASS + 49 SKIPPED). The exact installed source tree cannot be recovered from test evidence alone; confirm that the hotfix files were applied to the directory used by the runner, rather than assuming installation.

## Public safety

This report excludes raw JUnit/stdout/stderr, usernames, hostpaths, IP addresses and secrets. Original files should be retained privately and not auto-pushed into a public GitHub repository.