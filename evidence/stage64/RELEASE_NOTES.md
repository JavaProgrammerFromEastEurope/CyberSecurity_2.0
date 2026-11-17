# Stage 64 acceptance boundary / evidence index

Version 2.44.0. Strict regression results in this folder correspond to the
final Stage 64 Python source after version alignment and sqlmap permission
ordering fix. `regression_runs.json` enumerates three completed full tests.
`strict_full_N.stdout.log`, `.stderr.log`, `.exitcode` contain raw results.
`pre_additional_fixtures/`, `pre_sqlmap_approval_guard/` and
`pre_release_version_alignment/` preserve earlier completed PASS tests.
`LOCAL_TEST_CORRECTION.md` records the initial synthetic /proc fixture FAIL
whose original console output was not recorded separately.

`smoke_results.json` records compileall, CLI, PDF and worker help PASS, and
expected exit=3 for the read-only Ubuntu host/admission audits. A code 3
is NOT a passing production admission; it confirms fail-closed behavior.

The test host is Debian 13 with Python 3.13 and OpenSSL 3.5, systemd 257.
Ubuntu Server 26.10, cross-UID end-to-end, independent AppArmor enforcement,
service-manager restarts and authorized external scanner runs are not executed.
The production decision stays **BLOCKED/NO-GO**.

The original Stage 63 ZIP remains immutable; Stage 64 is cumulative. No
GitHub ref is force-updated or overwritten by this local build.
