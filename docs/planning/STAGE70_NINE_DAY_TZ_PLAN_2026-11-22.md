# Cyber Security 2.0 — ТЗ и девятидневный план (planning only)

**Проверено:** 2026-11-22. **Git baseline:** `prework_cybersecurity` commit `07780ffb85bf1d30e966897c2651a280abbf61d4`, application v2.45.0 / Stage65. **Источник требований:** предоставленное пользователем русскоязычное ТЗ на оркестратор ZAP/sqlmap/Nuclei. **Ограничение:** исторические v38.5 VM ZIP не являются слитыми исходниками этого репозитория.

**Оценка:** 27 *плановых* функциональных Stage-слотов за 9 рабочих дней (3/день). Они имеют обозначения `WP01..WP27`, а не открытые номера Stage. **Stage70 остаётся активным, Stage71 NOT_OPENED.** Девять дней — целевой срок feature-complete **lab candidate**, не обещание промышленной сертификации.

## 9-дневное распределение Stage

| День | Работы и последовательность |
|---|---|
| 1 | WP01 Git/ZIP provenance & Stage70 reconcile; WP02 local demo CLI→SQLite→dashboard/HTML; WP03 strict automated smoke+CI baselines |
| 2 | WP04 raw/normalized/asset schema migration; WP05 URL/method/provenance/scope Finding model; WP06 controller durable dispatch state machine |
| 3 | WP07 pinned loopback-authenticated ZAP Docker; WP08 bounded standard spider+passive; WP09 Ajax Spider sandbox or explicit UNSUPPORTED |
| 4 | WP10 explicitly approved ZAP active policy; WP11 tech fingerprint+pinned Nuclei templates; WP12 actual ZAP/Nuclei isolated lab E2E |
| 5 | WP13 local-only bounded sqlmap task REST API; WP14 immutable SQLi finding→reviewer→one-shot approval; WP15 ZAP auth-context Cookie/Token and log redaction |
| 6 | WP16 serial scanner orchestration with rate/resource cap; WP17 worker lease/timeout/cancel/recovery; WP18 immutable artifacts+partial/crash replay safety |
| 7 | WP19 normalized CVE/CWE, request method, raw references; WP20 multi-tool correlation/dedup+merged evidence; WP21 review/retest confidence without string-only Certain |
| 8 | WP22 executive and technical HTML/PDF; WP23 reproducible detail/assets/appendix; WP24 editable DOCX + parity and signed manifests |
| 9 | WP25 local operator API/dashboard UX and scope; WP26 real authorized lab/CI/performance/evidence; WP27 full regressions, upgrade/rollback, feature acceptance and defect backlog |

Приёмка каждого WP: работоспособный исполняемый код, реальные зависимости, отрицательные тесты, обратная совместимость, stdout/stderr/exit codes/TIMEOUT, SHA-256, reviewable commit. Третий WP каждого дня включает интеграционный gate зависимых WP. Критические баги устраняются сразу, а не откладываются до конца. После девятого дня основной фокус переходит на остаточные эксплуатационные и production-отказы.

## Покрытие загруженного ТЗ реальным репозиторием

Сводка на `v2.45.0`: **3 IMPLEMENTED, 20 PARTIAL, 8 MISSING, 1 NOT_PROVEN; 32 категории**. Это статусы наличия кода, а не подтверждение клиентской готовности.

| № | Требование | Статус |
|---|---|---|
| TZ-01 | Architecture/Controller/Workers/queue | PARTIAL |
| TZ-02 | Targets, authorization, scoped auth | PARTIAL |
| TZ-03 | scan_jobs state/timeouts | PARTIAL |
| TZ-04 | raw_findings JSON | PARTIAL |
| TZ-05 | normalized_findings expanded schema | PARTIAL |
| TZ-06 | report_assets screenshots/traces | MISSING |
| TZ-07 | scanner adapter contract | IMPLEMENTED |
| TZ-08 | ZAP secured daemon | PARTIAL |
| TZ-09 | ZAP Spider | MISSING |
| TZ-10 | ZAP passive alerts | PARTIAL |
| TZ-11 | ZAP Active Scan | MISSING |
| TZ-12 | ZAP Ajax Spider | MISSING |
| TZ-13 | sqlmap REST task lifecycle | MISSING |
| TZ-14 | sqlmap finding approval | PARTIAL |
| TZ-15 | sqlmap bounded evidence | PARTIAL |
| TZ-16 | Nuclei JSONL adapter | IMPLEMENTED |
| TZ-17 | Nuclei tech-directed templates | MISSING |
| TZ-18 | severity/confidence normalization | PARTIAL |
| TZ-19 | cross-tool semantic correlation | PARTIAL |
| TZ-20 | independent retest and reproduction | PARTIAL |
| TZ-21 | executive HTML report | PARTIAL |
| TZ-22 | technical findings/impact/fix | PARTIAL |
| TZ-23 | appendix raw results | PARTIAL |
| TZ-24 | PDF report | IMPLEMENTED |
| TZ-25 | optional Word DOCX | MISSING |
| TZ-26 | serialized workloads | PARTIAL |
| TZ-27 | timeouts/cancel/recovery | PARTIAL |
| TZ-28 | authenticated Cookie/Token ZAP contexts | MISSING |
| TZ-29 | false positive moderation | PARTIAL |
| TZ-30 | local API/dashboard | PARTIAL |
| TZ-31 | Docker/Compose/CI/real lab | PARTIAL |
| TZ-32 | OS/mac admission G01–G10/92 proof | NOT_PROVEN |

### Основания для классификации

`src/cybersec/scanners.py`: ZAP только passive; Nuclei фиксированные консервативные теги; sqlmap ограниченный CLI-адаптер, не REST task API. `sqlmap_gate.py` и `docs/STAGE_57_SQLMAP_APPROVAL.md`: одноразовая repository approval, но отсутствует внешне подтвержденная identity. `db.py`: `scan_artifacts` и `normalized_findings`, но не полная схема `raw_findings` + `report_assets`. `reports.py`, `pdf_reports.py`: HTML/PDF есть, DOCX не установлен. `scan_worker.py`, `api.py`, `dashboard.py`: реализованы базовые worker и loopback API, но продакшн-изоляция не доказана. `docs/STAGE70_SYNC_STATUS_2026-11-21.md`: существующие OS/MAC/evidence не обеспечивают production GO.

### Правила решений и безопасности

- ДЕНЬ 1 обязательно демонстрирует работающее приложение: `init → target add → job create --tool demo → job run → HTML → 127.0.0.1 dashboard`. Demo не выполняет сетевое сканирование.
- Никакого ZAP active scan, Ajax spider или sqlmap на неавторизованной цели. Только изолированная лаборатория, явная scope/approval, ограничение запросов/времени, аварийная остановка, отсутствие dump по умолчанию.
- Никакого повышения confidence до Certain только из-за слова `injection`. Не считать mock evidence доказательством настоящей уязвимости.
- Redis/PostgreSQL — варианты в ТЗ, а не обязательная замена SQLite без показателей масштабирования. DOCX обозначен опцией, но включён в WP24.
- Производственные блокеры не отключать ради демонстрации. **G01–G10: 0/10; доказанные сценарии: 0/92; PRODUCTION BLOCKED/NO-GO; Stage71 NOT_OPENED**.
- Каждый рабочий Stage коммитится в отдельную ветку/PR; GitHub commit SHA и CI-результаты фиксируются. Без `force push`, без секретов, без сырых VM журналов в публичном Git. Отчёты FULL + один LIGHT <10MB только если без потери критического исполняемого кода; иначе честно указать ограничение. Три независимые строгие регрессии для релизных границ; все FAIL/TIMEOUT хранятся вместе с PASS.
- Не обещать автономную ежедневную работу: каждый рабочий день требует отдельного фактического выполнения, проверки и публикации артефактов.

**Acceptance: feature-complete lab candidate не равно production GO.** При P0 FAIL ни финальный Stage, ни customer-ready не объявляются.
