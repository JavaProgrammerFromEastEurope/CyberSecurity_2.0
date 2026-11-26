# V75 PID Budget Causality — Safety and Acceptance Review

**Disposition:** BLOCKED/NO-GO, DAY-04 NOT_RUN, Stage71 NOT_OPENED.

| Threat / failure | Guard / evidence | Fail-closed action |
|---|---|---|
| Unsanctioned VM or host | Existing snapshot attestation, operator TTY YES and strict SSH host key | Refuse apply |
| Unexpected cgroup ancestry | Parent cgroup-v2 headroom and finite limits must be readable | Refuse A/B |
| Unsafe Docker mutation | Rendered Compose exact-diff only `zap.pids_limit` and pre-vetted `zap.shm_size`; digest-pinned images and unchanged seccomp/UID/network | Refuse startup |
| Runtime setting mismatch | Docker HostConfig actual `PidsLimit` and container `/sys/fs/cgroup/pids.max` | Mark trial BLOCKED |
| Same-cgroup cross-talk | Sequential AB/BA/AB runs; per-run and parent cgroup measurements, never simultaneous | Abort on unexpected parallelism |
| Failed browser or unusable window | Existing real primary WebDriver newSession → live window → exact internal fixture navigation | No AJAX admission |
| Empty/mis-scoped AJAX results | ZAP strict context, bounded search, AJAX result count > 0 and second passive queue drain | Remain NO-GO |
| Residual processes | Existing Firefox process-group quiescence and Docker Compose cleanup check | Abort next trial |
| Evidence tampering | byte-exact V74, 2 original ZIP hashes, nested SHA256SUMS and CRC, final source manifest | Reject artifact |
| Timestamps not causal | A/B observations classify association only; no fabricated causal guarantee | Mark NOT_ESTABLISHED |
| Historical source not supplied | `EVIDENCE(1).zip` absent in current session | Explicit provenance gap |

**Real lab acceptance:** six balanced, genuinely executed sequential A/B trials; all scoped WebDriver/fixture navigation and AJAX/second-passive gates evaluated with actual evidence; all cleanup and security assertions true; no skipped verification. Until then, not releasable to production.
