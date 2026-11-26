# Stage70 — ZAP Focused V75 PID Recovery R5 (candidate source checkpoint)

**Production: BLOCKED/NO-GO. DAY-04 NOT_RUN. Stage 71 NOT_OPENED.**

This commit checkpoints the source-code evolution after the previous Stage70 V62 feature-branch HEAD. It deliberately does **not** release Stage70, merge into `prework_cybersecurity` / `main`, or claim any completed six-trial Ubuntu A/B. The last user-supplied terminal log ended at R5 `ubuntu_ab_real RUNNING elapsed=56s`, with no final result supplied.

## Included in Git

- `effective-v75/`: the text-only V75 source snapshot, reconstructed from the checksum-pinned original V75 archive, followed by verified R3 structural cgroup-v2 root patch and R5 Compose baseline PID patch. Includes Python source, scripts, tests, documentation and source manifests.
- `patches/r3/`: R3 patch implementation, local AutoRunner with progress/heartbeat, negative tests and documentation.
- `diagnostics/r4/`: read-only Ubuntu Docker Compose delta forensics and tests.
- `patches/r5/`: R5 immutable-archive launcher, fail-closed Compose baseline patch and tests.
- `QA/R5_QA_SUMMARY.json`: locally confirmed 3 × (34 R5 + 56 inherited V75 target tests), with full legacy regression TIMEOUT/UNCONFIRMED.
- `GIT_SYNC_MANIFEST.json`, `SOURCE_GIT_SHA256.json`: lineage and per-file SHA-256 evidence for this Git snapshot.

## Important source vs. cumulative archive distinction

This Git directory is a **source-only checkpoint**, not an executable replacement for the cumulative R5 ZIP. `effective-v75/SOURCE_SHA256.json` and `SHA256SUMS.txt` were produced against the **full** extracted evidence-bearing V75 package. Their references to excluded QA, HISTORY, and EVIDENCE assets cannot be satisfied by this text-only Git snapshot. Actual verified launcher execution must use the separately preserved original R5 archive with all nested source and evidence; `patches/r5/r5_launcher.py` intentionally fails closed if those immutable originals are missing.

The full cumulative ZIP, historical backups, raw Ubuntu evidence, personal terminal transcripts, large QA stderr logs and any secrets are deliberately excluded from this public repository. SHA-256 values permit comparison against the user-held files. Do not copy raw VM files or unpublished sensitive data into Git.

## Current technical state

- The R3 cgroup structural-root correction has passed Ubuntu `cgroup_parent_preflight` for A=256 and B=384 in user evidence.
- R4 read-only Compose comparison showed only ZAP `pids_limit` and `shm_size` differences; R5 permits exactly these scoped, validated changes.
- R5 local review exits 0; three targeted strict batches have 90 PASS each. The complete inherited regression remains **unconfirmed after timeout**.
- The R5 Ubuntu A/B outcome is unknown: last supplied log ends mid-run. WebDriver navigation, AJAX Spider and second Passive Scan are NOT_VERIFIED for R5.
- No Active Scan authorization or production admission is implied. Preserve seccomp, NoNewPrivs, UID, network and scoped-target constraints.

See `GIT_SYNC_MANIFEST.json` for immutable ZIP hashes and `QA/R5_QA_SUMMARY.json` for granular local QA.
