# Cyber Security 2.0 — Stage70 V75 Compose Delta Read-Only Forensics R4

**Production BLOCKED/NO-GO. DAY-04 NOT_RUN. Stage71 NOT_OPENED.** Это диагностическое дополнение к V75 R3, а не новый Stage, не сертификат прохождения A/B и не изменение production admission.

## Что установлено из Ubuntu evidence

`EVIDENCE(20261126-193829).zip` SHA-256 `1fbf59d9b9f65e2c87b28ea73aa0adbd5f95d8007ebc6bae8c4eae38739376c7`:

- R3 реально прошёл `cgroup_parent_preflight=PASS` с родительским запасом 8991 при бюджетах 256/384;
- R1_A: `V75_COMPOSE_DELTA_INVALID` (exit 4), 35 targeted pytest PASS, до `docker compose up` и Firefox;
- `docker_after_cleanup` пуст, `v75_compose_quiescence=PASS`; **не путать с успешной жизнью контейнера**, который не был создан;
- все 4 роли для R1_A `UNKNOWN`, другие 5 A/B запусков `NOT_RUN`; WebDriver, AJAX, второй Passive Scan `NOT_RUN`;
- исходный Ubuntu ZIP и пользовательский контейнер сохранены без изменения байтов. Вложенные CRC/SHA-256 и файловые манифесты проверены.

**Причину конкретного различия Compose по одному коду `V75_COMPOSE_DELTA_INVALID` установить нельзя.** Для сохранения sandbox/UID/caps/network/NoNewPrivs нельзя ослабить Compose validator наугад.

## Что делает это дополнение

`Diagnose_Stage70_V75_Compose_Delta.command` на Mac: сначала проверяет SHA256 и CRC обоих оригинальных ZIP. `--mode review` работает полностью локально. Режим `--mode probe` требует интерактивного `READONLY`, проверяет отсутствие конкурирующего V75 AutoRunner (`flock`), затем через **StrictHostKeyChecking=yes, BatchMode=yes** подключается к заранее закреплённому `cyberadmin@192.168.64.2`.

В Ubuntu скрипт подтверждает pinned Git HEAD и digest образов, в памяти строит две одни и те же конфигурации `docker compose config --format json`, сначала baseline, затем overlay с `shm_size: 256m` и `pids_limit: 256`, затем с `384`. **Нет docker compose up/down, Docker-изменений, сканирования, доступа к публичным ресурсам или запуска Firefox.** Для overlay создаётся только временный каталог 0700 с YAML 0600, удаляемый после проверки. Реальные конфигурации, API key, переменные среды, содержимое Docker stderr и значения секретов никогда не передаются на Mac и не сохраняются.

В diagnostic ZIP попадут **только** изменившиеся пути и типы значений (`str`, `int`, `array`...), флаги соответствия ожидаемым 256 MiB и PID-бюджету, статус/exit code, SHA256 и аудит. Неизвестные/секретные ключи редактируются `<other>`, значения не публикуются. Даже если два допустимых поля совпадают, это лишь read-only диагноз, **не production PASS**.

## Как запустить

После распаковки архива R4 откройте Terminal:

```bash
cd "$HOME/Downloads/Stage70_V75_Compose_Delta_Forensics_R4_LT10MB"
bash Diagnose_Stage70_V75_Compose_Delta.command --mode review
bash Diagnose_Stage70_V75_Compose_Delta.command --mode probe
```

Введите `READONLY`, только если VM принадлежит вам и лабораторная область подтверждена. Команда не требует `APPLY` и не принимает PID-budgets вручную, поскольку воспроизводит точно два уже проверяемых значения 256/384. Исходный R3 AutoRunner **не запускать одновременно**.

Результат `STAGE70_V75_COMPOSE_DELTA_R4_<timestamp>.zip` с `.zip.sha256` сохраняется в `~/Documents/CyberSecurity_2.0/EVIDENCE/`. Приложите ZIP с новыми результатами и журнал Terminal. Если SSH или Compose render не доступны, будет `BLOCKED` и evidence со статусом; не отключайте защиты.

## Сохранение и тесты

В `originals/` побайтово сохранён точный накопительный `Stage70_V75_PID_Recovery_Cgroup_Root_Fix_R3_LT10MB.zip` и новый пользовательский `EVIDENCE(20261126-193829).zip`. Внутри R3 уже сохранён исходный V75, V74 и историческая цепочка. Никаких Git изменений/push. Манифест `SHA256SUMS.txt` проверяется повторно. Набор новых локальных тестов отражён в QA; **это не полная регрессия Stage70 и не Ubuntu E2E**.

## Итоги локальной QA R4

Три завершённые строгие регрессии нового диагностического компонента — **46 PASS каждая**, всего **138 PASS**, exit code 0, `ResourceWarning` и `DeprecationWarning` переведены в ошибки. Отдельная проверка `--mode review` PASS; в неподдерживаемой Linux x86_64 среде удалённый probe ожидаемо возвращает exit 4 (`NONROOT_UBUNTU_ARM64_REQUIRED`).

Предварительный smoke-тест выявил ошибку в классификации отсутствующего `services`; ошибка исправлена и повторная проверка PASS. Исходный журнал первой неудачи был перезаписан вторым smoke-прогоном — это отражено в `QA/R4_VALIDATION_REPORT.json`, не выдаётся за сохранённый. Полная унаследованная регрессия Stage70 **NOT_RERUN**: новые 46 тестов не заменяют её. Реальный SSH/Docker Compose config R4 **NOT_RUN**, пока пользователь не запустит `.command` в собственной VM.
