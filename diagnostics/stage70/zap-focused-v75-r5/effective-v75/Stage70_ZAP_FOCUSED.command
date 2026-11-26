#!/bin/bash
set -euo pipefail
HERE="$(cd "$(dirname "$0")" && pwd -P)"
exec /usr/bin/env python3 "$HERE/mac_run.py" "${1:-review}"
