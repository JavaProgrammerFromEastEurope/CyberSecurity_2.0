#!/bin/bash
# Double-click this file in macOS Finder, or run with bash from Terminal.
set -u
# Avoid suspending an active A/B while local SSH may continue unattended.
trap '' TSTP
HERE="$(cd "$(dirname "$0")" && pwd -P)"
if command -v python3 >/dev/null 2>&1; then
  PYTHONUNBUFFERED=1 python3 -u -B "$HERE/auto_runner.py" "$@"
  rc=$?
else
  echo 'BLOCKED: python3 missing (requires Python 3.9+)' >&2
  rc=4
fi
printf '\nStage70 V75 PID AutoRunner exit code: %s\n' "$rc"
if [ "$#" -eq 0 ] && [ -t 0 ]; then
  printf 'Для закрытия окна нажмите Enter: '
  IFS= read -r _unused || true
fi
exit "$rc"
