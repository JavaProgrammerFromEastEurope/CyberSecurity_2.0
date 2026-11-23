#!/usr/bin/env bash
# Stage70 Day02: macOS bash 3.2 compatible; never admit production.
set -eo pipefail
umask 077
ROOT="$(cd "$(dirname "$0")" && pwd)"
cd "$ROOT"
MODE="$1"
if [[ "$#" -ne 1 || "$MODE" != "--review" && "$MODE" != "--check" && "$MODE" != "--run" ]]; then
  echo "Usage: bash Stage70_DAY02_DEMO.command --review|--check|--run" >&2; exit 2
fi
for value in "$CYBERSEC_EXECUTION_MODE" "$CYBERSEC_RUNTIME_MODE"; do
  value_lc="$(printf '%s' "$value" | tr '[:upper:]' '[:lower:]')"
  if [[ "$value_lc" == "production" || "$value_lc" == "prod" ]]; then
    echo "BLOCKED: production environment" >&2; exit 4
  fi
done
if [[ "$EUID" -eq 0 && "$CYBERSEC_DAY01_ALLOW_ROOT_CI" != "1" ]]; then
  echo "BLOCKED: run as an unprivileged user" >&2; exit 4
fi
PY=python3
if [[ -x "$ROOT/.venv/bin/python" ]]; then PY="$ROOT/.venv/bin/python"; fi
if [[ "$MODE" == "--review" ]]; then
  for p in src/cybersec/day02.py src/cybersec/db.py tools/day02_e2e.py; do
    [[ -f "$p" ]] || { echo "MISSING: $p" >&2; exit 4; }
  done
  echo 'STAGE70_DAY02=WP04_WP05_WP06 OFFLINE_ONLY'
  echo 'PRODUCTION=BLOCKED/NO-GO STAGE71=NOT_OPENED'
  exit 0
fi
"$PY" -c 'import sys; assert sys.version_info >= (3,11); import cybersec.day02,cybersec.db,reportlab' || {
  echo 'Install in a virtual environment: .venv/bin/python -m pip install -e ".[dev]"' >&2; exit 3;
}
echo 'DAY02_DEPENDENCIES=PASS'
if [[ "$MODE" == "--check" ]]; then exit 0; fi
mkdir -p "$ROOT/.day02_evidence"
RUN="$ROOT/.day02_evidence/run_$(date -u +%Y%m%dT%H%M%SZ)_$RANDOM"
"$PY" "$ROOT/tools/day02_e2e.py" --evidence-dir "$RUN"
echo "DAY02_EVIDENCE_DIR=$RUN"
