# Cyber Security 2.0 — Stage70 V75 PID Recovery AutoRunner R2: Live Console Progress

**Исправление вывода, не новый Stage и не новый V75 исходного ядра.** Вложенный оригинальный V75 PID Recovery Candidate сохранён неизменным, SHA-256 `11d3add1a47a86a14ba9cb652e8f3a4261a499d1139d27a968d8063b23059d18`.

## Исправлено

- Вместо `pipe.read(1024)` используется readiness-селектор + `os.read`: приглашения терминала и stdout/stderr (включая данные без `\n`) показываются сразу.
- `PYTHONUNBUFFERED=1`, `python3 -u`, фиксированные стадии LOCAL_REVIEW 1/4–4/4 и heartbeat каждые 8 секунд в длительном A/B; отсутствие вывода больше не маскируется как «зависание».
- После `SNAPSHOT` показывается напоминание: исходный вложенный runner требует **ЕЩЁ ОДНО реальное `YES`**; это подтверждение не подставляется автоматически.
- `Ctrl+Z` в новой оболочке запрещён: приостановка родительского процесса могла оставлять SSH/Firefox выполняться без оператора. Для безопасного прерывания используйте `Ctrl+C`; после этого подтвердите состояние и очистку VM, прежде чем запускать повторно.
- При тайм-ауте/`Ctrl+C` локальная группа дочерних процессов получает SIGTERM/SIGKILL, exit code фиксируется в evidence. **Удалённая quiescence от этого НЕ доказана.**
- В `PROGRESS.jsonl` сохраняются timestamp UTC, стадия, события START/RUNNING/EXIT/TIMEOUT/INTERRUPTED. Полные stdout/stderr и exit codes сохраняются независимо.
- Исходные лимиты, sandbox, seccomp, NoNewPrivs, UID, политики и запрет Active Scan не менялись.

При извлечении архиватором, который не сохраняет UNIX-права, допускается запуск через `bash Run_Stage70_V75_PID_Recovery.command`. Штатный ZIP содержит `.command` с исполняемым битом.

## ПЕРЕД ПОВТОРНЫМ ЗАПУСКОМ

В предыдущем журнале есть `^Z` / `zsh: suspended bash Run_Stage70_V75_PID_Recovery.command`. **Не запускайте новый A/B, пока не выясните судьбу остановленного процесса и Ubuntu/SSH-дочерних задач**. На том же терминале: `jobs -l`. Если действительно есть остановленное задание, верните его в foreground: `fg %1` (номер уточните по `jobs -l`), после чего завершите штатно или `Ctrl+C`; отдельно проверьте SSH и Docker/Firefox quiescence в Ubuntu. Не применяйте `killall`/`pkill` вслепую. Новый runner имеет lock и откажется от конкурентного старта.

## Запуск (два ZIP)

Скачайте архив R2 и резервный ZIP SHA-256 в `~/Downloads`:

```bash
cd "$HOME/Downloads"
BASE="Stage70_V75_PID_Recovery_AutoRunner_Console_Progress_R2_LT10MB"
unzip -oq "${BASE}_SHA256_CHECKSUM.zip" "${BASE}.zip.sha256"
shasum -a 256 -c "${BASE}.zip.sha256" && unzip -oq "${BASE}.zip"
cd Stage70_V75_PID_Recovery_AutoRunner
bash Run_Stage70_V75_PID_Recovery.command
```

Сначала выполните только `--mode review`, если не подтверждён ресурс родительской cgroup и состояние старого задания. Для реального A/B требуется осознанное `APPLY`, два заранее верифицированных конечных бюджета A/B, `LAB`, `SNAPSHOT` и второе `YES`. Значения бюджетов **не выбираются автоматически**.

**Прикладной status:** Production BLOCKED/NO-GO; Stage 71 NOT_OPENED; DAY-04 NOT_RUN; реальный A/B и WebDriver/AJAX/second Passive в этом пакете NOT_RUN.

## Проверки R2

Три независимых строгих запуска 21 launcher unit/negative tests, проверка частичного промпта через реальный PTY, проверка timeout и heartbeat; полноценные 1074+ Stage70 регрессии повторно не засчитываются, т.к. этот пакет меняет только внешний AutoRunner и сохраняет V75 без изменения байтов. В доказательствах сохранены журналы всех тестов и локального review.

## Происхождение

`PATCHES/` содержит точные unified diffs к исходному AutoRunner R1. Его SHA-256 находится в `QA/ORIGINAL_AUTORUNNER_SHA256.txt`. Исходный V75 ZIP и sidecar сохранены побайтово.

## Контракты безопасности

- Исходный V75 (9 632 078 байт) находится внутри комплекта **без изменения байтов**, SHA-256 `11d3add1a47a86a14ba9cb652e8f3a4261a499d1139d27a968d8063b23059d18`.
- Встроенный V75 содержит точный V74 и исторические пользовательские evidence. Программа проверяет ZIP целиком и извлекает во временную закрытую папку; не переписывает и не пушит оригинальные исходники.
- SSH использует фиксированный адрес/ключ из исходного V75, строгую проверку известного host key и запрещает интерактивный ввод пароля (`BatchMode=yes`).
- Не отключаются Docker sandbox, seccomp, NoNewPrivs, UID, capabilities; Active Scan не используется.
- Никакой `--apply` не запускается без согласия на лабораторию, snapshot, A/B budgets и второго терминального `YES`.
- При отсутствии реального полного подтверждения основного WebDriver fixture navigation, scoped AJAX Spider и второго Passive Scan: **Production BLOCKED/NO-GO**, **DAY-04 NOT_RUN**, **Stage 71 NOT_OPENED**.
- Опыт с PID budget может завершиться отказом Firefox, даже если локальная QA PASS; никакой причинности по одному совпадению с `pids.events` не утверждается.

В целях безопасности не открывайте присланные неизвестными лицами `.command` и не запускайте от `sudo`. Этот пакет предназначен только для вашей изолированной лаборатории.
