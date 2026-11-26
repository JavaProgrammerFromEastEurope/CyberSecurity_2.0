#!/bin/bash
# macOS autoexec. No remote activity except after explicit operator approval.
set -u
trap '' TSTP
HERE="$(cd "$(dirname "$0")" && pwd -P)"
if command -v python3 >/dev/null 2>&1; then
  PYTHONUNBUFFERED=1 PYTHONDONTWRITEBYTECODE=1 python3 -u -B "$HERE/r5_launcher.py" "$@"
  rc=$?
else
  echo 'BLOCKED: Python 3.9+ required' >&2
  rc=4
fi
printf '\nStage70 V75 R5 exit code: %s\n' "$rc"
if [ "$#" -eq 0 ] && [ -t 0 ]; then
  printf 'Для закрытия окна нажмите Enter: '
  IFS= read -r _unused || true
fi
exit "$rc"
