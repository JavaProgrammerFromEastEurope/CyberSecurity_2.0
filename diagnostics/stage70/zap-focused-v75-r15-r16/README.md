# Stage 70 V75: R15/R16 source and CI review (LAB ONLY)

This PR is a **public, privacy-screened, partial source synchronization** of the
R15/R16 diagnostics. It does **not** contain the complete cumulative ZIP
chain or the private Ubuntu evidence. Do not treat GitHub CI green as an
Ubuntu end-to-end pass or authorization for production.

Exact R15 cumulative main archive SHA-256:
`15de8a7066674f6d667494de5afef670cb3cd99fe7839e4ef8cb34cbb4506c53`.
Exact R15 QA archive SHA-256:
`25503b37df091f1fc14815d8be8c0b411039a0c2f95d2a9d9fc7b2f92cb56f72`.
Historical evidence `EVIDENCE(20261127-200004).zip`:
`87c2bfd977ff0c273cc3f804c1324ac9a45dd181ea1e41af9cb330da2031099a`.

**Observed:** 384 PID budget had two LAB_PASS trials, each three resolved
in-scope AJAX URLs and second Passive Scan; 256 budget had FAIL trials with
75 and 4 PID denials. 24-cell matrix: 7 classified, 9 UNKNOWN, 8 absent.
No causal claim from observational data.

The tracked `r16_phase_final.py` is the exact read-only phase classifier
from the R16 work-in-progress candidate; its unit tests are synthetic and
do not contact Docker, ZAP, Firefox, or any target. The R16 runtime driver,
nested source packages, private evidence and VM launch tooling remain
outside this public PR until an independent reviewed source sync.

**Invariants:** A=256, B=384, no Active Scan, lab scope only,
sandbox/seccomp/NoNewPrivs unchanged, manual READONLY/APPLY/LAB/SNAPSHOT/YES
admission unchanged, fail-closed. DAY-04 NOT_RUN, Stage71 NOT_OPENED,
Stage70 and Production BLOCKED/NO-GO.

Github Actions here tests only local, public, reproducible contracts.
R16 full three strict regressions and R16 Ubuntu E2E are NOT YET VERIFIED.
