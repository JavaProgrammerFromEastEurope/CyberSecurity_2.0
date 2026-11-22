# Stage70 Day01 (WP01–WP03): Functional application acceptance

**Baseline:** application v2.45.0 / Stage65 on `prework_cybersecurity` `07780ffb85bf1d30e966897c2651a280abbf61d4`. Planning PR #4 parent `c4111167286da7e2f6eb788c4f32167d57cae397`. Day01 implementation branch: `feature/stage70-day01-wp01-wp03-20261122`.

**Two different artifacts:**
- GitHub app `src/cybersec`, package `cybersec-orchestrator`. This is what an operator runs.
- Original Stage70 v38.5 G09 ZIP(s) / VM evidence are **host admission/diagnostic harnesses**, not an installed copy of the app. Their bytes are preserved in conversation artifacts, **not** published to the public GitHub repo. Do not assert they are merged into this product.

**Goal:** real offline app lifecycle CLI → SQLite → demo job → stored artifact → synthetic finding → HTML/PDF → loopback API/dashboard. The demo adapter guarantees `network_requests=0` for scanner execution; HTTP client probes only access a locally started `127.0.0.1` API. This is neither a real assessment nor production approval.

## macOS / Ubuntu developer run

From this exact branch (not from a v38.5 G09 harness ZIP):

```bash
git clone --branch feature/stage70-day01-wp01-wp03-20261122 https://github.com/JavaProgrammerFromEastEurope/CyberSecurity_2.0.git
cd CyberSecurity_2.0
python3 -m venv .venv    # Python >=3.11
.venv/bin/python -m pip install -e '.[dev]'
bash Stage70_DAY01_DEMO.command --review
bash Stage70_DAY01_DEMO.command --check
bash Stage70_DAY01_DEMO.command --run
```

On macOS without a usable Unicode `.ttf` in standard paths, set `CYBERSEC_DAY01_FONT_PATH=/absolute/path/to/locally-installed.ttf` before check/run. No fonts, credentials or private keys are bundled in the release. Do not use `sudo`. Use a dedicated development environment. The launcher **refuses** an explicit production environment.

Evidence will be retained under `.day01_evidence/run_<timestamp>_<nonce>/`, excluded from Git. Key artifacts: `smoke_result.json`, `state/cybersec.db`, `report.html`, `report.pdf`, PDF checksum manifest. Each child CLI call retains stdout/stderr/exit code in the smoke JSON. Keep the evidence private.

## Acceptance matrix

| WP | Requirement | Evidence / expected |
|---|---|---|
| WP01 | Git/ZIP source reconciliation | exact pinned GitHub commit and locally SHA-verified Stage70 originals; no false merge claim |
| WP02 | launch real app | `day01_smoke.py` checks CLI target and job statuses, SQLite target/job/finding/artifact rows, escaped HTML with synthetic finding, nonempty PDF with magic `%PDF-`, API health 200, dashboard 200, unauthorized request 401, authorized request 200 |
| WP03 | strict repeatability | 3 independent CI runners on Python 3.13, warning-as-error full pytest, --review/--check/--run, denial of production mode, per-file SHA-256 and retained logs; general CI 3.11/3.12/3.13/3.14 |

## Confirmed source-level P0 issues and fixes

- `src/cybersec/reports.py` used a backslash-escaped literal **inside an f-string expression**, which is illegal in Python 3.11 and 3.12. Moved the HTML fragment construction outside the f-string with no intended content change.
- `pyproject.toml` omitted `pypdf` from the dev test dependencies despite `tests/test_stage61_pdf.py` importing it, causing reproducible full-suite failure. `pytest-asyncio` was likewise absent although its configuration option was set. Day01 adds these dev-only dependencies.
- All initial CI FAIL and TIMEOUT outcomes remain accessible via GitHub Actions. Do **not** count these failing runs as successful regressions.

## Trust boundary

- No real ZAP/Nuclei/sqlmap scan occurs in Day01.
- No actual macOS host execution is claimed from remote GitHub Actions. GitHub Actions Ubuntu runner is a real process execution but it is not the user's macOS or Ubuntu VM.
- Testing does not prove lifecycle MAC/cgroup confinement, trustworthy snapshot approvals or any of 92 production acceptance scenarios.
- Public Github must not contain user VM raw archives, credential/token, snapshot file, production keys or output reports with customer data.
- **Production BLOCKED/NO-GO; G01–G10 0/10; production scenarios 0/92; Stage 71 NOT_OPENED.**

## Day02 input contract

Proceed to WP04–WP06 only after the Day01 smoke and strict CI pass. Keep the app runnable. Implement an additive, migrated `raw_findings`/`normalized_findings`/`report_assets` model, stable Finding schema, authorization and URL scope gates and a bounded durable controller. Include idempotent migrations, rollback analysis, negative authorization tests, and compatibility evidence. Do not auto-enable active scanners.
