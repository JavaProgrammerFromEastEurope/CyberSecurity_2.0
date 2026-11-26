#!/bin/bash
set -u
cd "$(dirname "$0")" || exit 4
python3 -B diagnose_mac.py "$@"
rc=$?
printf '\nStage70 V75 Compose read-only diagnosis exit code: %s\n' "$rc"
if [ -t 0 ]; then read -r -p 'Нажмите Enter для закрытия окна: ' _ || true; fi
exit "$rc"
