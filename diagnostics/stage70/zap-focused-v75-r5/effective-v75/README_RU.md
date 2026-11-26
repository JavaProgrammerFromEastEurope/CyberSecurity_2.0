# Cyber Security 2.0 — Stage70 V75 PID Budget Causality & WebDriver Recovery

**Отдельный кандидат V75 — `BLOCKED/NO-GO`.** Это не переименование и не подмена опубликованного V75 WebDriver Stage Boundary. GitHub HEAD и исходный Git tree не изменены. DAY-04 — `NOT_RUN`, Stage 71 — `NOT_OPENED`.

## Преемственность и доказательства

- Исходный V74 (`9 188 012` байт, SHA-256 `8c4108e3af996e053188c5da55d04454c1891f876e333f8d9910a52d49ecf9a0`) сохранён побайтово как `HISTORY/ORIGINAL_V74_UNCHANGED.zip.xz`. Команда `python3 -B restore_v74.py verify` распаковывает его для независимой проверки SHA-256, CRC и истории.
- `EVIDENCE(20261126-172555).zip` (19 запусков) и `EVIDENCE(20261126-180821).zip` (20 запусков, включая V74 17:36 UTC) находятся **без изменения байтов** внутри `EVIDENCE/USER_EVIDENCE_PAIR.tar.xz`. Это сплошное LZMA-сжатие двух точных ZIP; восстановление через `tarfile` и проверка обоих SHA-256 в `audit_latest_v75_candidate.py`.
- Исходный архив с буквальным именем `EVIDENCE(1).zip` из предыдущего запроса **не представлен в этой сессии** и не подменён новым evidence. См. `EVIDENCE/SOURCE_GAP.json`.
- Исходная лабораторная Git ревизия: `9de9fe0c2fc4e31d695aa9f3bd4594a0a5ecf5dd`; исторический GitHub baseline `f16ed1c5b13175cdd2c351b4281201bf6b5b24ee` сохранён.

## Функциональные изменения кандидата

1. Read-only числовая телеметрия: `pids.current`, `pids.max`, `pids.peak`, `pids.events`, `pids.events.local`, `memory.events`, процессы/потоки, `RLIMIT_NPROC`, `Threads`, `Seccomp`, `NoNewPrivs`, monotonic time. Недоступные поля представлены как `null`, а не нулём. Сырые PID, профили, cookie, токены и полные stdout Firefox не экспортируются в агрегированную телеметрию.
2. Проверка доступных родительских cgroup v2 до A/B. Неподтверждённая иерархия, неизвестный лимит, недостаточный headroom и недоступные счётчики — **BLOCKED**. Никаких записей в `/sys/fs/cgroup`.
3. Оператор задаёт **два различных конечных PID-бюджета** (от 64 до 512). Они только примеры в командах ниже, не рекомендованные значения. Разрешены ровно два изменения относительно исходного рендера Docker Compose: `zap.shm_size=256m` и `zap.pids_limit=БЮДЖЕТ`. SHA-pinned Docker images, сети, UID, capabilities, seccomp и `NoNewPrivs` не изменяются.
4. Каждый A/B прогон выполняет штатную цепочку V74: отдельные Firefox 0/1/3 Marionette-когорты, контроль WebDriver Session/окна/навигации **на точную внутреннюю fixture**, после допуска — scoped AJAX Spider с реальными ненулевыми результатами и второй Passive Scan. Нельзя засчитывать диагностическую пробу как результат основного WebDriver gate.
5. A/B runner проводит три повторения в последовательности **A1, B1, B2, A2, A3, B3**; всего шесть последовательных запусков и 24 ячейки наблюдения (0/1/3 клиента + WebDriver). Между запусками обязательны проверенное завершение Compose и отсутствие остаточных контейнеров. Неудачное испытание сохраняется; непроверенная очистка немедленно останавливает всю серию.
6. Даже шесть успешных наблюдений не доказывают, что PID-лимит — единственная причина ошибки браузера; классификатор выдаёт `...NO_CAUSALITY`. Текущие исторические сигналы — только временная корреляция.

## Проверки на Mac

Загрузить **два ZIP** в `~/Downloads`: основной архив и отдельный `*_SHA256_CHECKSUM.zip` (не TXT и не `.sha256` напрямую).

```bash
cd "$HOME/Downloads"
BASE="Stage70_ZAP_API_AJAX_SPIDER_PASSIVE_FOCUSED_V75_PID_BUDGET_CAUSALITY_RECOVERY_CANDIDATE_LT10MB"
unzip -oq "${BASE}_SHA256_CHECKSUM.zip" "${BASE}.zip.sha256"
shasum -a 256 -c "${BASE}.zip.sha256" && unzip -oq "${BASE}.zip"
cd "$BASE"
python3 -B restore_v74.py verify
python3 -B audit_evidence_v74.py
python3 -B audit_latest_v75_candidate.py
python3 -B audit_lineage.py
bash Stage70_ZAP_FOCUSED.command review
```

Обычный диагностический запуск V75 (без A/B): `bash Stage70_ZAP_FOCUSED.command apply`. Требует интерактивного `YES`, авторизованной выделенной UTM Ubuntu ARM64 VM и заранее подтверждённого snapshot.

Контролируемый A/B (только после проверки реальных бюджетов и согласования в лаборатории):

```bash
bash Run_V75_AB.command --budget-a 128 --budget-b 256 \
  --lab-consent --vm-snapshot-confirmed
```

`128` и `256` — **синтаксические примеры**, а не утверждённые или безопасные значения. Runner повторно проверяет иерархию cgroup и завершение предыдущего испытания, подключается по SSH с включённым StrictHostKeyChecking, сохраняет все возвратные коды/stdout/stderr и evidence в `~/Documents/CyberSecurity_2.0/EVIDENCE/`. Пароли и ключи в архив не включены.

## Результаты и ограничения

Локальные строгие регрессии не заменяют реальный запуск в Ubuntu. A/B-кейсы, WebDriver-навигация, AJAX Spider и второй Passive Scan на этом кандидате пока **NOT_RUN**, пока не передано проверяемое свидетельство из авторизованной UTM-лаборатории. Доказательств для Production GO нет. Active Scan отключён. Изменение на хосте, привилегированное выполнение, обход sandbox и произвольная цель не допускаются.
