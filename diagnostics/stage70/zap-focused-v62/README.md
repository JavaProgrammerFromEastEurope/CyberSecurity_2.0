# Stage 70 — ZAP Focused V62 (reproducible source delta)

## Provenance and GitHub comparison

The product's last Stage 70 Day03 branch head before this commit was `9de9fe0c2fc4e31d695aa9f3bd4594a0a5ecf5dd` (`feature/stage70-day03-wp07-wp09-20261124`). The GitHub default `prework_cybersecurity` was 35 commits behind it; `main` contains only README. There were **no published GitHub Releases** on 2026-11-25. Do **not** rewrite the product's default branch or modify its pinned lab sources.

This directory includes a **byte-reproducible V61 → V62 diagnostic runner source delta**, not a claim that the whole V62 standalone runner is already integrated into `src/cybersec` or that Stage 70 passed its production gate. `v61_to_v62.patch` changes `zap_focus_vm.py`, `mac_run.py`, `run_strict_regressions.py`, and `README_RU.md`. `overlays/` contains six new V62 source/QA-manifest files. Source SHA-256 values are in `GIT_SYNC_MANIFEST.json`.

### Reproduce safely (with the original V61 ZIP, without mutating it)

```bash
python3 diagnostics/stage70/zap-focused-v62/restore.py \
  --v61-zip Stage70_ZAP_API_AJAX_SPIDER_PASSIVE_FOCUSED_V61_DIRECT_MARIONETTE_BASELINE_LT10MB.zip \
  --out-dir /tmp/cybersec-stage70-v62-reconstructed
```

`restore.py` requires an empty destination, verifies input ZIP SHA-256, blocks unsafe archive members, invokes `patch --batch --forward -p1` only in the new directory, copies source overlays, reconstructs a valid V61 history dependency and validates all ten output hashes. It does not reproduce canonical V62 QA logs or full ZIP metadata byte-for-byte. The canonical V62 archive and previous local evidence remain in the user-provided cumulative ZIP, not in the public Git branch.

### Ubuntu V62 result, November 25 2026

- ZAP API 2.17.0 PASS, ordinary Spider 100%, first Passive Scan drained; 14 passive alerts are unconfirmed.
- Targeted Ubuntu tests 35 PASS; Docker cleanup PASS.
- **Native Firefox Marionette handshake PASS** (diagnostic only): independent Firefox can start and accept a loopback connection.
- GeckoDriver still returns WebDriver `/session` HTTP 500; `MARIONETTE_HANDSHAKE` and `SANDBOX_DENIED` were observed. Underlying cause **not proven**; no successful WebDriver navigation.
- AJAX Spider and second Passive Scan NOT_RUN. Active Scan false; production BLOCKED/NO-GO; DAY-04 NOT_RUN; Stage 71 NOT_OPENED.

The full raw V62 Ubuntu evidence is **not** committed to this public GitHub repo. `V62_UBUNTU_REDACTED_RESULT.json` records only selected diagnostics and SHA-256 of the original evidence ZIP. The canonical local V62 package reports three strict local regression rounds of 314 PASS each; this does **not** replace Ubuntu E2E acceptance.

This push is a version-control checkpoint, **not** a production release or Stage 70 closure.
