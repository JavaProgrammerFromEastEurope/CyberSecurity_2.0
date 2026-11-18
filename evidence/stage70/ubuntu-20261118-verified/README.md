# Cyber Security 2.0 — Ubuntu Stage 70 verified evidence audit

**Assessment: BLOCKED / NO-GO for production.** The newest three full strict LOCAL regressions on Ubuntu Server 26.10 passed; independent Ubuntu OS-enforced acceptance has not run.

## Integrity and provenance

- Original uploaded evidence ZIP SHA-256: `8c36e9d3dd6bf106bd7f7d1a8901650493a69adf4a532a8bfd6cf8d410038a19`.
- ZIP archive integrity: PASS.
- Nested evidence ZIPs and their provided SHA-256 sidecars verified: **8/8 PASS**.
- Per-run internal `SHA256SUMS` entries verified: **152 PASS, zero mismatches**.
- `full_strict_*.json` compared with JUnit XML counts; stdout/stderr SHA-256 matched recorded values.
- Compared with the previous uploaded evidence ZIP: **154 existing files byte-identical, 0 missing, 22 new files**.

## All retained regressions

| UTC run ID | Full regression #1 / #2 / #3 | PASS / FAIL / SKIPPED per regression |
|---|---|---|
| 20261117T202835Z_kd4r183b | FAIL / FAIL / FAIL | 548P/3F/49S · 548P/3F/49S · 548P/3F/49S |
| 20261117T203028Z_ja2tjsn5 | FAIL / FAIL / FAIL | 548P/3F/49S · 548P/3F/49S · 548P/3F/49S |
| 20261117T205818Z_r0sei3a5 | FAIL / FAIL / FAIL | 548P/3F/49S · 548P/3F/49S · 548P/3F/49S |
| 20261117T210728Z_40k39jvn | FAIL / FAIL / FAIL | 548P/3F/49S · 548P/3F/49S · 548P/3F/49S |
| 20261117T214117Z_1u6y19fc | PASS / PASS / PASS | 551P/0F/49S · 551P/0F/49S · 551P/0F/49S |
| 20261118T131052Z_gi5m_iwl | PASS / PASS / PASS | 551P/0F/49S · 551P/0F/49S · 551P/0F/49S |
| 20261118T132815Z_8yxqrxnl | FAIL / PASS / PASS | 550P/1F/49S · 551P/0F/49S · 551P/0F/49S |
| 20261118T135338Z_jukigbth | PASS / PASS / PASS | 554P/0F/49S · 554P/0F/49S · 554P/0F/49S |

The 17 November initial failures were `test_pdf_unicode_and_manifest`, `test_pdf_both_profiles`, and `test_pdf_html_same_filtered_findings` (missing system Unicode TTF). A later intermittent `test_stage66_unix_peer_uid_kernel_and_generic_denial` encountered `ConnectionRefusedError` because the Unix socket file appeared before the server was ready to accept connections. All historical failures are retained in the original private evidence.

## Latest verified series

- Run ID: `stage70_20261118T135338Z_jukigbth`.
- Execution mode: `local` (not Ubuntu OS-enforced acceptance).
- Three completed strict runs: **554 PASS, 49 SKIPPED, 0 FAIL/ERROR per run**, each exit code `0`.
- Test collection: 603 test cases per run.
- Durations: 50.87, 30.41, 33.70 seconds.
- `ResourceWarning` and `DeprecationWarning` both configured as errors.
- Local evidence verdict: `TESTS_COMPLETE`; production authorization: `false`.
- The previous PDF failures and intermittent Stage 66 socket readiness failure did not recur in this series. This supports the test fix but does not prove the absence of all future races.

## Confirmed environmental capabilities

Ubuntu 26.10; Python 3.14; OpenSSL 4; systemd 261; AppArmor kernel enabled; unified cgroup v2 with `cgroup.kill`; `pidfd_open`; distinct service UIDs detected.

## Still unverified — production acceptance blockers

- All **49 Ubuntu opt-in integration tests skipped** per latest run; no kernel acceptance result.
- AppArmor controller enforcing profile absent (`controller_mac_enforcing=false`); worker enforcing label unverified.
- Independent root fixture controller absent (`root_fixture_controller=false`); hardware-backed monotonic root and recovery-permit authority unverified.
- Worker UID/service binding, root-owned systemd unit, `INVOCATION_ID` and independent service-manager lifecycle evidence unverified.
- Same-UID legacy MAC denial, cgroup escape resistance, replay/rollback, IPC spoofing, and independent publication/recovery claims unverified end-to-end.

**Security decision:** `BLOCKED/NO-GO`. Local regression success must not be reported as production `GO`.

## Publication policy

This text is a **sanitized audit summary**. Original JUnit XML, stdout, stderr, host inventories, system paths and evidence ZIPs remain private and were not uploaded to public GitHub. Store their SHA-256 as a reference; share originals only through a reviewed private channel.