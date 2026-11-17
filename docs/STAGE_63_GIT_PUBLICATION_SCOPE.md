# Stage 63 Git publication scope

Source archive: `cyber_securuty_2.0_stage_63.zip`
SHA-256: `a1146e669d7b9b69cb6c19bae1d8d90fddb17ed6576a76b340363745a73c262e`.

This branch is an isolated import of the chat's Stage 63 `v2.43.0`. It intentionally does not overwrite the independent `prework_cybersecurity` Stage 63, whose Linux/LSM features are incompatible with the imported release numbering. The Git history is anchored to the existing default-branch commit only for ancestry; its tree represents the imported application snapshot.

The cumulative ZIP is the source of truth for the complete archived evidence, including historical stdout/stderr, exit codes, PASS/FAIL logs and manifest. The repository import preserves source code, tests and documentation, not the complete bulky generated evidence archive.

External ZAP, Nuclei and sqlmap scanners were not executed for Git publication. Ubuntu Server production admission remains **BLOCKED / NO-GO**.

Do not merge with the other Stage 63 implementation before reviewing the release numbering and architecture conflicts.
