# Cyber Security 2.0 — Stage70 V75 PID Recovery — Cgroup Structural Root Fix R3

## Статус

Production **BLOCKED/NO-GO**. DAY-04 **NOT_RUN**, Stage71 **NOT_OPENED**. Это новый вариант запуска существующего Stage70 V75 PID Recovery, а не новый Stage и не production-допуск. Ни один реальный Ubuntu A/B в R3 здесь не выполнялся.

## Причина исправления — данные реальной Ubuntu VM

Исходный evidence `EVIDENCE(20261126-192657).zip` (SHA-256 `f7314719b987da0ae3f21db3e560234bb8fec8cb3c14c81273877a7a42a8bc34`):

| Уровень от текущей cgroup | pids.current | pids.max |
| --- | ---: | ---: |
| 0 | 3 | max |
| 1 | 7 | 8998 |
| 2 | 7 | max |
| 3: /sys/fs/cgroup (root) | отсутствует | отсутствует |

Отказ прежнего preflight: `PARENT_CURRENT_UNKNOWN`. На видимом узле с конечным лимитом запас 8998−7=8991 слотов; это не доказывает всю ресурсную готовность, и значения могут изменяться между измерениями.

## Исправление с fail-closed

Оригинальный накопительный архив V75 включён *побайтово без изменений* и сначала проверяется по закреплённому SHA-256 `11d3add1a47a86a14ba9cb652e8f3a4261a499d1139d27a968d8063b23059d18` и CRC.

`root_fix_r3.py` изменяет **только временную копию** `pid_recovery.py` и пересчитывает в ней SOURCE_SHA256.json/SHA256SUMS.txt. Старые `zap_focus_vm.py`, `mac_pid_ab_runner.py`, seccomp, NoNewPrivs, sandbox, Docker network и scope не изменяются.

Исключение применяется только к *самому верхнему узлу* и только при подтверждённых условиях:
- единственное cgroup2 монтирование по ожидаемой точке с `mount root=/`;
- корень не symlink, содержит читаемые `cgroup.controllers` и `cgroup.subtree_control`, где `pids` активен;
- `os.lstat` подтверждает ENOENT одновременно для root `pids.current` и root `pids.max`;
- все видимые промежуточные родители остаются обязательными; минимум один содержит **конечный** `pids.max`, известный `pids.current`, проверенный headroom.

Если недоступен mountinfo, хотя бы один промежуточный счетчик, файл является symlink, нет конечного родительского лимита или headroom недостаточен — `BLOCKED`.

**Ограничение:** монтирование внутри cgroup namespace само по себе не доказывает видимость всех внепространственных родителей хоста. До реального прохождения всех проверок в вашей VM это не production-гарантия. Даже если preflight PASS, A/B и quiescence должны быть доказаны independently.

## Установка на macOS

Поместите два выдаваемых ZIP в `~/Downloads`, затем:

```bash
cd "$HOME/Downloads"
BASE="Stage70_V75_PID_Recovery_Cgroup_Root_Fix_R3_LT10MB"
unzip -oq "${BASE}_SHA256_CHECKSUM.zip" "${BASE}.zip.sha256"
shasum -a 256 -c "${BASE}.zip.sha256" && unzip -oq "${BASE}.zip"
cd Stage70_V75_PID_Recovery_Cgroup_Root_Fix_R3
bash Run_Stage70_V75_PID_Recovery.command --mode review
```

Режим `review` не подключается к Ubuntu. Для лабораторного A/B запускайте без `--mode review`, затем `APPLY`, два явных бюджета (ранее использованы 256/384), `LAB`, `SNAPSHOT`, `YES` после фактического подтверждения всех предпосылок. **Не запускайте при незавершённых процессах предыдущего испытания или непроверенной quiescence.** Никогда не используйте production/public targets.

Вывод stdout/stderr и heartbeat каждые 8 секунд сохранён из R2. Локальные и Ubuntu evidence архивы сохраняются в `~/Documents/CyberSecurity_2.0/EVIDENCE/` вместе с SHA256/exitcodes.

## QA

Новые проверки R3 — три строгих прогона ×41 тест (123 PASS), локальный R3 `review` exit 0. Проверены пропущенные intermediate PID-файлы, подмена symlink, неверный mountinfo, отключённый контроллер, отсутствующий конечный лимит и недостаточный headroom.

**Повторная полная унаследованная Stage70 регрессия не подтверждена** — её попытка не завершилась в управляющем тайм-ауте. Нельзя считать 41-тестовый набор заменой полной регрессии. Все ограничения задокументированы в QA. Старые журналы R2 сохранены, включая TIMEOUT.

В `originals/` сохранены новые пользовательские ZIP-evidence и Terminal Markdown без изменения байтов.
