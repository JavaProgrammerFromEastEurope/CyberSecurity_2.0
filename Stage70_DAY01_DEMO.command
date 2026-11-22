#!/usr/bin/env bash
# Stage70 Day01 local-only OFFLINE DEMO launcher. Never admits production.
set -euo pipefail
umask 077
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$ROOT"
MODE="${1:---review}"
if [[ "$#" -ne 1 || "$MODE" != "--review" && "$MODE" != "--check" && "$MODE" != "--run" ]]; then
  echo "Usage: bash Stage70_DAY01_DEMO.command --review|--check|--run" >&2; exit 2
fi
for name in CYBERSEC_EXECUTION_MODE CYBERSEC_RUNTIME_MODE; do
  value="${!name:-}"
  value_lc="$(printf "%s" "$value" | tr "[:upper:]" "[:lower:]")"
  if [[ "$value_lc" == production || "$value_lc" == prod ]]; then
    echo "FAIL_CLOSED: production environment $name is set; refusing demo" >&2; exit 4
  fi
done
if [[ "${EUID:-$(id -u)}" -eq 0 && "${CYBERSEC_DAY01_ALLOW_ROOT_CI:-}" != 1 ]]; then
  echo "FAIL_CLOSED: do not run the demo as root" >&2; exit 4
fi
PY="python3"
if [[ -x "$ROOT/.venv/bin/python" ]]; then PY="$ROOT/.venv/bin/python"; fi
if [[ "$MODE" == "--review" ]]; then
  echo "DAY01_MODE=OFFLINE_DEMO_NOT_SECURITY_SCAN"
  echo "PRODUCTION=BLOCKED/NO-GO STAGE71=NOT_OPENED"
  for f in pyproject.toml src/cybersec/cli.py tools/day01_smoke.py; do
    [[ -f "$f" ]] || { echo "REQUIRED_SOURCE_MISSING=$f" >&2; exit 4; }
    echo "SOURCE_PRESENT=$f"
  done
  if command -v git >/dev/null && git rev-parse --is-inside-work-tree >/dev/null 2>&1; then
    echo "GIT_COMMIT=$(git rev-parse HEAD)"
  fi
  exit 0
fi
"$PY" -c 'import sys; assert sys.version_info >= (3,11), "Python>=3.11 required"; import cybersec,reportlab,cryptography' || {
  echo "Install the product into an isolated venv: python3 -m venv .venv && .venv/bin/python -m pip install -e . " >&2; exit 3;
}
FONT="${CYBERSEC_DAY01_FONT_PATH:-}"
if [[ -z "$FONT" ]]; then
  for candidate in "/usr/share/fonts/truetype/dejavu/DejaVuSans.ttf" \
                   "/usr/share/fonts/truetype/liberation2/LiberationSans-Regular.ttf" \
                   "/Library/Fonts/Arial.ttf" \
                   "/Library/Fonts/DejaVuSans.ttf" \
                   "/System/Library/Fonts/Supplemental/Arial.ttf"; do
    if [[ -f "$candidate" ]]; then FONT="$candidate"; break; fi
  done
fi
if [[ -z "$FONT" || ! -f "$FONT" ]]; then
  echo "PDF_FONT_REQUIRED: Set CYBERSEC_DAY01_FONT_PATH to an installed Unicode .ttf" >&2
  exit 3
fi
echo "DEMO_DEPENDENCIES=OK"
echo "PDF_FONT_PATH=$FONT"
echo "PRODUCTION=BLOCKED/NO-GO"
if [[ "$MODE" == "--check" ]]; then exit 0; fi
mkdir -p "$ROOT/.day01_evidence"
RUN_DIR="$ROOT/.day01_evidence/run_$(date -u +%Y%m%dT%H%M%SZ)_$RANDOM"
echo "EVIDENCE_DIR=$RUN_DIR"
"$PY" "$ROOT/tools/day01_smoke.py" --font-path "$FONT" --evidence-dir "$RUN_DIR"
echo "DEMO_COMPLETED: the demo sends ZERO scanner network requests"
echo "OPEN_LOCAL_REPORT=$RUN_DIR/report.html"
