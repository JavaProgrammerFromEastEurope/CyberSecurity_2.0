#!/usr/bin/env bash
set -euo pipefail
umask 077
ROOT="$(cd "$(dirname "$0")" && pwd)"
cd "$ROOT"
if [[ "$#" -lt 1 ]]; then echo 'Usage: --review|--check|--run [--authorize-local-lab] [--ajax]' >&2; exit 2; fi
MODE="$1"; shift
for key in CYBERSEC_RUNTIME_MODE CYBERSEC_EXECUTION_MODE; do
  raw="${!key:-}"
  lc="$(printf '%s' "$raw" | tr '[:upper:]' '[:lower:]')"
  if [[ "$lc" == 'production' || "$lc" == 'prod' ]]; then echo 'BLOCKED/NO-GO: production mode' >&2; exit 4; fi
done
if [[ "${EUID:-$(id -u)}" == 0 && "${CYBERSEC_DAY01_ALLOW_ROOT_CI:-0}" != 1 ]]; then echo 'BLOCKED: refuse root' >&2; exit 4; fi
PY=python3
if [[ -x "$ROOT/.venv/bin/python" ]]; then PY="$ROOT/.venv/bin/python"; fi
case "$MODE" in
  --review) [[ "$#" == 0 ]] || exit 2; "$PY" -m cybersec.day03_zap --review ;;
  --check) [[ "$#" == 0 ]] || exit 2; "$PY" -m cybersec.day03_zap --check ;;
  --run)
    [[ "${1:-}" == '--authorize-local-lab' ]] || { echo 'BLOCKED: explicit --authorize-local-lab required' >&2; exit 4; }
    shift
    AJAX_ARGS=()
    if [[ "${1:-}" == '--ajax' ]]; then AJAX_ARGS=(--ajax); shift; fi
    [[ "$#" == 0 ]] || exit 2
    mkdir -p "$ROOT/.day03_evidence"
    OUT="$ROOT/.day03_evidence/run_$(date -u +%Y%m%dT%H%M%SZ)_$RANDOM"
    "$PY" -m cybersec.day03_zap --run --authorize-local-lab --evidence-dir "$OUT" "${AJAX_ARGS[@]}"
    echo "DAY03_EVIDENCE_DIR=$OUT" ;;
  *) echo 'Usage: --review|--check|--run' >&2; exit 2 ;;
esac
