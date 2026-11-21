# Stage 61 — Client-Ready PDF Reporting

Offline PDF A4 reports use ReportLab and a local Unicode TTF (default DejaVu Sans on Ubuntu). No scanner, network, browser, or external binary is invoked.

`cybersec report pdf --output reports/client.pdf --profile technical`

Use `--profile executive`, existing `--target-id`, `--job-id`, `--severity`, `--priority` filters, and `--font-path /path/to/font.ttf` where needed.

The adjacent `.pdf.manifest.json` records SHA-256, file size, and counts. SHA-256 is **not** a digital signature; protect the manifest independently.

HTML and PDF share the repository export and filter function. PDF deliberately includes reproduction as *Not recorded* if absent in source data; it does not invent steps. Report content is escaped as text; no active URL fetch or external content loading. Fields are truncated to 12,000 characters to bound layout.

**Limits:** Reports do not prove scan coverage, vulnerability validity, authorization, or completeness. PDF and manifest are each atomically replaced but not a two-file transaction. Embedded font is not distributed in the archive. Ubuntu integration and process supervision deferred to Stage 62.

## Verification

Stage61 focused 5/5 PASS; full Python suite 282 PASS with one unraisable SQLite ResourceWarning (not warning-free). First strict run failed during pytest-asyncio configuration, fixed by explicit fixture loop scope; retry returned 0. Scanner tools were not executed. Raw stdout/stderr and exit codes are retained in `evidence/stage61`.
