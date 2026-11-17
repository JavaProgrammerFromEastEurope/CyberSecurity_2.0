# Cyber Security 2.0 Stage 70 — Ubuntu evidence audit (2026-11-17)

**Verdict: BLOCKED / NO-GO.** This report summarizes supplied local-run evidence and **does not attest Ubuntu production acceptance**.

## Source integrity

- Supplied source ZIP SHA-256: `ed36c8ee0826ffb0962057a5e443a897761843d77a26baa96a3f1ceff64b1d1a`
- Outer ZIP integrity and SHA-256: **PASS** (matches supplied `.sha256` file)
- 4 nested ZIP integrity and matching SHA-256 files: **PASS**
- 4 internal manifests / 76 SHA-256 entries: **PASS**
- Note: checksums were supplied with the evidence; they prove consistency, not independent origin.

## Strict local regression outcomes

| Local run ID (2026-11-17 UTC) | Strict runs | Per-run passed | Failed | Skipped | Exit code | Result |
| --- | ---: | ---: | ---: | ---: | ---: | --- |
| 20261117T202835Z | 3 | 548 | 3 | 49 | 1 | FAIL |
| 20261117T203028Z | 3 | 548 | 3 | 49 | 1 | FAIL |
| 20261117T205818Z | 3 | 548 | 3 | 49 | 1 | FAIL |
| 20261117T210728Z | 3 | 548 | 3 | 49 | 1 | FAIL |

- 12/12 full strict regressions completed, **0/12 passed**.
- All three repeated failures are from `tests/test_stage61_pdf.py`:
  - `test_pdf_unicode_and_manifest`
  - `test_pdf_both_profiles`
  - `test_pdf_html_same_filtered_findings`
- Recorded error: `RuntimeError: Unicode TrueType font unavailable; supply --font-path to a local TTF`.
- 49 Ubuntu opt-in tests were **SKIPPED** in every run. These are not successful OS tests.

## Host read-only preflight

Confirmed in uploaded host records: Ubuntu 26.10, Python 3.14.8, systemd 261, OpenSSL 4.0.3, unified cgroup v2, `cgroup.kill` available, AppArmor module enabled. Later runs report distinct service UIDs configured, but do **not** establish working constrained cross-UID services.

Still blocked: enforcing worker/controller AppArmor policy, independent kernel MAC denial tests, root-owned systemd service units and invocation evidence, service UID binding, independent admission and monotonic recovery permit authority, live restart and rollback demonstrations.

## Remediation and next evidence

1. In the Ubuntu VM, install Ubuntu-packaged Unicode TTF fonts (e.g. `fonts-dejavu-core` and `fonts-liberation2`) and verify `/usr/share/fonts/truetype/dejavu/DejaVuSans.ttf` exists.
2. Re-run `tests/test_stage61_pdf.py` and three full local strict regressions; retain all previous failure evidence.
3. Separately provision reviewed enforcing AppArmor policies, real systemd units and external root authority, then run the opt-in integration suite with no skipped mandatory checks.
4. Retain NO-GO until the independent OS-enforced evidence is complete.

## Publication boundary

This public-safe audit includes no raw host paths, JUnit XML, process logs, IPs, email addresses, or embedded test fixture values. Original evidence must remain in controlled storage and is **not** uploaded to a public repository.

## Repository lineage

The evidence-only Git branch is based on the last verified published `stage65-v2.45.0` branch. It **does not include Stage 70 source code** or imply that Stage 70 was committed to GitHub. The supplied Stage 70 ZIP remains the separate cumulative software artifact.