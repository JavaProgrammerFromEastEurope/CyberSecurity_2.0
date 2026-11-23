# Stage 70 — Day 02 / WP04–WP06: additive evidence and durable demo orchestration

**Git base:** Day 01 PR #5, commit `52a0a02a04916d753f941c464bf1ac5a272d529b`. **Day:** 2026-11-23. **Status:** laboratory source candidate; NOT production-accepted.

## WP04 — SQLite migration

`cybersec.day02.apply_migration` is called from the original `initialize` after the legacy schema. It is idempotent and forward-only (`stage70-day02-wp04-06-v1`), executed in a SAVEPOINT within the existing connection. The migration adds `raw_findings`, `report_assets`, `controller_plans`, `controller_steps` and nullable fields `normalized_findings.http_method/reproduction_steps/raw_ref/confidence_basis`. Existing CLI/API, `scan_artifacts`, and historical rows are preserved.

**Important limitation:** the historical `SCHEMA` uses `executescript` before this migration, so the entire legacy initialization is not one atomic transaction; only the Day02 migration is rolled back atomically. Take a SQLite backup before upgrading; roll back by restoring the backup, **not** by automatically dropping new tables.

An actual **copy** of the user-provided macOS Day01 SQLite was migrated and integrity-checked without changing the original: one target, one job, one finding, one artifact before and after, `PRAGMA integrity_check = ok`.

## WP05 — scope and finding evidence

New opt-in `ingest_raw_finding` atomically saves original JSON with SHA-256 and a normalized finding linked via `raw_ref`, under server-side target authorization. `require_scope` checks exact origin, path-segment prefix, and denies ambiguous encoded paths, userinfo, path traversal, fragments, and origin/port/scheme mismatch. `add_report_asset` stores bounded local media with SHA-256 and deduplication. `get_enriched_finding` exposes new fields, without changing legacy `Finding.to_dict` signatures.

**Known boundary:** legacy `Repository.add_finding` is kept for API compatibility; it is **not** upgraded to the new admission model and must not serve as a production authority. A textual confidence basis is **not** independently validated proof of a vulnerability. The new raw-ingest path is not yet wired into automatic external scanner workers.

## WP06 — serial demo-only controller

`DemoController.create_plan` and `advance` implement durable SQLite, idempotency key rejection on payload conflict, `BEGIN IMMEDIATE` concurrency, serial demo job scheduling and terminal failure blocking. No automatic replay after `failed` or `cancelled` is permitted. **Only tool `demo` is admitted**. ZAP, Nuclei and sqlmap are explicitly refused until separately authorized and tested in later roadmap days. Controller does **not** execute scanner jobs; it only queues safe demo metadata.

## Run locally on Mac / Linux

Use Python >=3.11 from a virtual environment, install `pip install -e '.[dev]'`. Do not use sudo. From repository root:

```bash
bash Stage70_DAY02_DEMO.command --review
bash Stage70_DAY02_DEMO.command --check
bash Stage70_DAY02_DEMO.command --run
```

The run writes evidence in `.day02_evidence/` (ignored by Git) and performs **zero scanner network requests**. Existing Day01 launcher remains available and should continue passing `--run`.

## Verification / release gate

- Three independent full warning-as-error regressions, stdout/stderr/exit code/timeout/SHA-256 retained; negative test cases include scope, authorization, replay, migration drift, race, and fail-closed controller behavior.
- Real offline Day02 E2E and Day01 compatibility E2E; SQLite actual Day01-copy migration and integrity check.
- FULL and exactly one LIGHT source ZIP under 10,000,000 bytes, SHA/CRC and independent unpack checks.
- Original Day01 cumulative ZIPs and original user evidence are retained **outside public GitHub**. Do not publish raw private VM evidence, personal paths, credentials, snapshot files or production keys.
- Production G01–G10 **0/10**, proven scenarios **0/92**; **BLOCKED/NO-GO**; Stage 71 **NOT_OPENED**.

## Next workday

Day 03 WP07–WP09: secure local ZAP daemon and explicitly authorized passive/Spider/Ajax discovery. Start only from this exact tested code+evidence; do not call mocks real scanning evidence.
